#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.10"
# dependencies = ["cryptography>=42"]
# ///
"""Manage carcc.github.io short links: opaque /s/CODE links and public vanity /NAME/ aliases.

Two namespaces, so nothing collides:

  /s/CODE   opaque link. CODE is 8+ random Crockford base32 characters and is ALSO the key:
            the repo holds only s/d/<id>.json ciphertext, where both <id> and the AES key come
            from one slow PBKDF2 derivation of CODE. Without the code, the destination is not
            readable, and walking the repo gives ids, not URLs. Codes are always random; a
            chosen word has too little entropy, so memorable names are vanity aliases instead.
  /NAME/    vanity alias, public on purpose (aliases.json + a NAME/index.html stub). Deep links
            /NAME/any/page forward to the same path under the target.

This is obfuscation against casual walking, not secrecy: anyone can clone the repo and guess
codes offline (see ReadMe.md § Short links for the numbers). Never shorten a secret URL.

The browser half (assets/links.js) mirrors derive()/decrypt() with WebCrypto. Keep the two in
step: change SALT, ITERATIONS or the blob format in both, and bump the version in SALT.

Usage (from the repo root; `uv` installs `cryptography` on first run):
  scripts/shortlink.py add URL [--length N] [--ledger PATH]
  scripts/shortlink.py edit CODE URL          # same code, new destination
  scripts/shortlink.py show CODE
  scripts/shortlink.py rm CODE
  scripts/shortlink.py alias NAME URL         # vanity /NAME/ -> URL
  scripts/shortlink.py unalias NAME
  scripts/shortlink.py record CODE|NAME       # (re)submit a link's record row
  scripts/shortlink.py check                  # validate blobs + aliases

add/edit/alias take --what TEXT and --used-in TEXT for the record. Every change is recorded
first (see RECORD_FORM); if that fails, nothing is written. It writes files only; review and
commit yourself, with a message that does not name the URL.
"""

import argparse
import base64
import datetime
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parent.parent
SITE = "https://carcc.github.io"
DATA = ROOT / "s" / "d"
ALIASES = ROOT / "aliases.json"

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32: no I L O U
SALT = b"carcc.github.io/s/v1"
ITERATIONS = 600_000
MIN_LENGTH = 8
ORG = "CaRCC"
# Top-level names the site itself uses; an alias may not take them.
RESERVED = {"s", "assets", "scripts", "404", "404.html", "index.html", "aliases.json",
            "readme.md", ".nojekyll", ".git", ".github"}

# The record: every add/edit/rm/alias/unalias is submitted to a Google Form (no sign-in) whose
# responses land in the private "carcc.github.io links" sheet, so codes are written down
# somewhere other than this public repo. Anyone could submit junk, which is accepted: a real
# row's Blob id is the one `show CODE` derives, and its file exists here; junk can't fake that.
RECORD_FORM = ("https://docs.google.com/forms/d/e/"
               "1FAIpQLScJKzZEFBS8JACWQdpcLCsfhfZQ6rEdgBdfh8tmXk8Xxq5yJw/formResponse")
RECORD_FIELDS = {  # Forms questionId (hex) per field; the form posts them as entry.<decimal>
    "code": "765a5a49", "short": "162aeaef", "id": "5f249f8d", "url": "1c47ef92",
    "kind": "107b0de2", "op": "428136a7", "what": "28d7a1f2", "used": "47f8b816",
    "source": "4fa49109"}


def normalize(code: str) -> str:
    """Canonical form of a typed code: upper-case, hyphens dropped, O->0 and I/L->1."""
    c = code.strip().upper().replace("-", "").replace("O", "0").replace("I", "1").replace("L", "1")
    bad = sorted(set(c) - set(ALPHABET))
    if bad:
        raise SystemExit(f"invalid character(s) in code: {''.join(bad)}")
    return c


def derive(code: str) -> tuple[bytes, str]:
    """(AES key, blob id) from one PBKDF2 run, so finding the id costs as much as the key."""
    master = hashlib.pbkdf2_hmac("sha256", code.encode(), SALT, ITERATIONS, 32)
    key = hmac.new(master, b"key", hashlib.sha256).digest()
    lid = hmac.new(master, b"id", hashlib.sha256).hexdigest()[:24]
    return key, lid


def encrypt(code: str, url: str) -> tuple[str, dict]:
    key, lid = derive(code)
    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, json.dumps({"u": url}).encode(), lid.encode())
    return lid, {"v": 1, "iv": base64.b64encode(iv).decode(), "ct": base64.b64encode(ct).decode()}


def decrypt(code: str) -> tuple[str, str]:
    key, lid = derive(code)
    path = DATA / f"{lid}.json"
    if not path.exists():
        raise SystemExit(f"no link for code {code}")
    blob = json.loads(path.read_text())
    pt = AESGCM(key).decrypt(base64.b64decode(blob["iv"]), base64.b64decode(blob["ct"]), lid.encode())
    return lid, json.loads(pt)["u"]


def check_url(url: str) -> str:
    if not re.match(r"^https?://[^\s]+$", url):
        raise SystemExit(f"not an http(s) URL: {url!r}")
    return url


def write_blob(lid: str, blob: dict) -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    (DATA / f"{lid}.json").write_text(json.dumps(blob) + "\n")


def append_ledger(path: str | None, entry: dict) -> None:
    """The plaintext code->URL record lives OUTSIDE the repo, or nowhere."""
    if not path:
        return
    p = Path(path).expanduser().resolve()
    if p == ROOT or ROOT in p.parents:
        raise SystemExit(f"refusing to write the ledger inside the repo: {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def source() -> str:
    """Who and what made a record row, so a junk row (which won't have this) stands out."""
    r = subprocess.run(["git", "-C", str(ROOT), "config", "user.name"], capture_output=True, text=True)
    git = f" (git: {r.stdout.strip()})" if r.returncode == 0 and r.stdout.strip() else ""
    return f"{getpass.getuser()}{git} via shortlink.py"


def record(a, **row) -> None:
    """Submit one row to the record form BEFORE changing any file, so a failed record changes
    nothing. --no-record skips it (offline use) and says so."""
    row = {"source": source(), "what": getattr(a, "what", "") or "", "used": getattr(a, "used_in", "") or "",
           **row}
    if getattr(a, "no_record", False):
        print("warning: --no-record, so add this to the links sheet by hand: "
              + json.dumps(row), file=sys.stderr)
        return
    data = urllib.parse.urlencode({f"entry.{int(RECORD_FIELDS[k], 16)}": v for k, v in row.items()}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(RECORD_FORM, data=data), timeout=30) as resp:
            if resp.status != 200:
                raise urllib.error.HTTPError(RECORD_FORM, resp.status, "unexpected status", None, None)
    except urllib.error.HTTPError as e:
        hint = (" (the form requires sign-in: untick 'Restrict to users in …' in its settings)"
                if e.code == 401 else "")
        raise SystemExit(f"recording failed: HTTP {e.code}{hint}; nothing was changed. "
                         "Retry, or use --no-record and record it by hand.")
    except urllib.error.URLError as e:
        raise SystemExit(f"recording failed: {e.reason}; nothing was changed. "
                         "Retry, or use --no-record and record it by hand.")


def cmd_add(a) -> None:
    url = check_url(a.url)
    if a.length < MIN_LENGTH:
        raise SystemExit(f"--length must be at least {MIN_LENGTH} (shorter codes are brute-forceable)")
    while True:
        code = "".join(secrets.choice(ALPHABET) for _ in range(a.length))
        lid, blob = encrypt(code, url)
        if not (DATA / f"{lid}.json").exists():
            break
    record(a, code=code, short=f"{SITE}/s/{code}", id=lid, url=url, kind="short", op="add")
    write_blob(lid, blob)
    append_ledger(a.ledger, {"code": code, "url": url, "id": lid,
                             "created": datetime.date.today().isoformat(), "op": "add"})
    print(f"{SITE}/s/{code}")
    rec = "NOT recorded (--no-record)" if a.no_record else "recorded the code in the links sheet"
    print(f"  wrote s/d/{lid}.json and {rec}. Commit the file with a message that doesn't\n"
          f"  name the URL.", file=sys.stderr)


def cmd_edit(a) -> None:
    code = normalize(a.code)
    lid, _ = decrypt(code)  # must already exist
    _, blob = encrypt(code, check_url(a.url))
    record(a, code=code, short=f"{SITE}/s/{code}", id=lid, url=a.url, kind="short", op="edit")
    write_blob(lid, blob)
    append_ledger(a.ledger, {"code": code, "url": a.url, "id": lid,
                             "created": datetime.date.today().isoformat(), "op": "edit"})
    print(f"{SITE}/s/{code} -> {a.url}")


def cmd_show(a) -> None:
    code = normalize(a.code)
    lid, url = decrypt(code)
    print(f"{SITE}/s/{code} -> {url}  (s/d/{lid}.json)")


def cmd_rm(a) -> None:
    code = normalize(a.code)
    lid, url = decrypt(code)
    record(a, code=code, short=f"{SITE}/s/{code}", id=lid, url=url, kind="short", op="rm")
    (DATA / f"{lid}.json").unlink()
    print(f"removed s/d/{lid}.json (it stays in git history)")


def cmd_record(a) -> None:
    """(Re)submit the record row for an existing code or alias: a backfill, or after --no-record."""
    m = load_aliases()
    if a.ref.lower() in m:
        name = a.ref.lower()
        record(a, short=f"{SITE}/{name}/", url=m[name], kind="alias", op="record")
        print(f"recorded {SITE}/{name}/")
        return
    code = normalize(a.ref)
    lid, url = decrypt(code)
    record(a, code=code, short=f"{SITE}/s/{code}", id=lid, url=url, kind="short", op="record")
    print(f"recorded {SITE}/s/{code}")


def load_aliases() -> dict:
    return json.loads(ALIASES.read_text()) if ALIASES.exists() else {}


def save_aliases(m: dict) -> None:
    ALIASES.write_text(json.dumps(dict(sorted(m.items())), indent=2) + "\n")


def org_repo_names() -> set[str] | None:
    """Lower-cased CaRCC repo names (a repo with Pages takes its own path), or None if gh can't say."""
    if not shutil.which("gh"):
        return None
    r = subprocess.run(["gh", "api", "--paginate", f"orgs/{ORG}/repos", "--jq", ".[].name"],
                       capture_output=True, text=True)
    return {n.lower() for n in r.stdout.split()} if r.returncode == 0 else None


STUB = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Redirecting…</title>
<link rel="canonical" href="{url}">
<script>location.replace({url_js} + location.search + location.hash);</script>
<meta http-equiv="refresh" content="0; url={url}">
</head>
<body>
<p>Moved to <a href="{url}">{url}</a>.</p>
</body>
</html>
"""


def cmd_alias(a) -> None:
    name, url = a.name.lower(), check_url(a.url)
    if not re.match(r"^[a-z0-9][a-z0-9-]*$", name):
        raise SystemExit("alias names are lower-case letters, digits and hyphens")
    m = load_aliases()
    if name in RESERVED:
        raise SystemExit(f"{name!r} is reserved by the site")
    if name in m and not a.force:
        raise SystemExit(f"alias {name!r} already points to {m[name]} (use --force to repoint)")
    if (ROOT / name).exists() and name not in m:
        raise SystemExit(f"{name}/ already exists in the repo and is not an alias")
    repos = org_repo_names()
    if repos is None:
        print(f"warning: couldn't list {ORG} repos (gh); check no repo is named {name!r}", file=sys.stderr)
    elif name in repos:
        raise SystemExit(f"a {ORG} repo is named {name!r}; its Pages site would shadow the alias")
    record(a, short=f"{SITE}/{name}/", url=url, kind="alias", op="edit" if name in m else "add")
    m[name] = url
    save_aliases(m)
    (ROOT / name).mkdir(exist_ok=True)
    (ROOT / name / "index.html").write_text(STUB.format(url=url, url_js=json.dumps(url)))
    print(f"{SITE}/{name}/ -> {url}")


def cmd_unalias(a) -> None:
    name = a.name.lower()
    m = load_aliases()
    if name not in m:
        raise SystemExit(f"no alias {name!r}")
    record(a, short=f"{SITE}/{name}/", url=m[name], kind="alias", op="rm")
    del m[name]
    save_aliases(m)
    shutil.rmtree(ROOT / name, ignore_errors=True)
    print(f"removed alias /{name}/")


def cmd_check(_a) -> None:
    problems = 0
    for p in sorted(DATA.glob("*.json")) if DATA.exists() else []:
        try:
            blob = json.loads(p.read_text())
            ok = (re.fullmatch(r"[0-9a-f]{24}", p.stem) and blob.get("v") == 1
                  and len(base64.b64decode(blob["iv"])) == 12 and base64.b64decode(blob["ct"]))
        except Exception:
            ok = False
        if not ok:
            problems += 1
            print(f"BAD blob {p.relative_to(ROOT)}")
    m = load_aliases()
    for name, url in m.items():
        stub = ROOT / name / "index.html"
        if not stub.exists() or url not in stub.read_text():
            problems += 1
            print(f"BAD alias {name}: stub missing or stale")
    n = len(list(DATA.glob('*.json'))) if DATA.exists() else 0
    print(f"{n} short link(s), {len(m)} alias(es), {problems} problem(s)")
    sys.exit(1 if problems else 0)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    ledger = dict(metavar="PATH", default=os.environ.get("SHORTLINK_LEDGER"),
                  help="also append code/url to this JSON-lines file OUTSIDE the repo (env SHORTLINK_LEDGER)")

    def recorded(p, notes=True):
        """Options for the verbs that submit a row to the record form."""
        if notes:
            p.add_argument("--what", metavar="TEXT", help="what the link is, for the record")
            p.add_argument("--used-in", metavar="TEXT", help="where it's used (a deck, a flyer…)")
        p.add_argument("--no-record", action="store_true", help="skip the record form (offline); record by hand")

    p = sub.add_parser("add", help="new opaque /s/CODE link")
    p.add_argument("url"); p.add_argument("--length", type=int, default=MIN_LENGTH)
    p.add_argument("--ledger", **ledger); recorded(p); p.set_defaults(func=cmd_add)
    p = sub.add_parser("edit", help="repoint an existing code")
    p.add_argument("code"); p.add_argument("url"); p.add_argument("--ledger", **ledger)
    recorded(p); p.set_defaults(func=cmd_edit)
    p = sub.add_parser("show", help="decrypt a code"); p.add_argument("code"); p.set_defaults(func=cmd_show)
    p = sub.add_parser("rm", help="delete a code's blob"); p.add_argument("code")
    recorded(p, notes=False); p.set_defaults(func=cmd_rm)
    p = sub.add_parser("alias", help="public vanity /NAME/ -> URL")
    p.add_argument("name"); p.add_argument("url"); p.add_argument("--force", action="store_true")
    recorded(p); p.set_defaults(func=cmd_alias)
    p = sub.add_parser("unalias", help="remove a vanity alias"); p.add_argument("name")
    recorded(p, notes=False); p.set_defaults(func=cmd_unalias)
    p = sub.add_parser("record", help="(re)submit the record row for an existing CODE or alias NAME")
    p.add_argument("ref", metavar="CODE|NAME"); recorded(p); p.set_defaults(func=cmd_record)
    p = sub.add_parser("check", help="validate blobs and alias stubs"); p.set_defaults(func=cmd_check)
    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
