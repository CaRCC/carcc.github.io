# carcc.github.io

The CaRCC organization's GitHub Pages site, served at <https://carcc.github.io/>.
It is a plain HTML/CSS link page plus a static URL shortener for CaRCC links.

## Links

There are two kinds, in separate namespaces so they can't collide:

- **Vanity aliases**, `carcc.github.io/NAME/`: public and readable on purpose,
  for links you print on slides. Deep links (`/NAME/any/page`) forward to the
  same path when the target ends in `/`. Current aliases are in
  [aliases.json](aliases.json).
- **Short links**, `carcc.github.io/s/CODE`: opaque. `CODE` is 8 random
  characters, and the repo stores only ciphertext, so the destinations can't be
  read by browsing the repo.

Manage both with `scripts/shortlink.py`. It needs [uv](https://docs.astral.sh/uv/),
which installs the `cryptography` dependency on first run. Run it from the
repo root:

```sh
scripts/shortlink.py add https://example.org/long/url   # prints carcc.github.io/s/CODE
scripts/shortlink.py edit CODE https://example.org/new  # same code, new destination
scripts/shortlink.py show CODE
scripts/shortlink.py rm CODE
scripts/shortlink.py alias NAME https://example.org/    # vanity /NAME/
scripts/shortlink.py unalias NAME
scripts/shortlink.py check                              # validate everything
```

The script only writes files. Review and commit them yourself, and **don't put
the URL in the commit message**. `alias` refuses names the site uses, existing
aliases (unless `--force`) and CaRCC repo names, because a repo with Pages
turned on takes its own path.

## How short links work

- A code is 8+ characters of Crockford base32
  (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`). Readers may type it in lower case, with
  hyphens, or with O/I/L for 0/1/1.
- One PBKDF2-SHA256 run (600,000 iterations, a fixed site salt) turns the code
  into a master secret. HMAC then derives the blob id and the AES-256-GCM key
  from it. Deriving the id and the key in the same slow step means guessing a
  code costs the same whether you're looking for an id or a URL.
- `s/d/<id>.json` holds only the IV and the ciphertext. The id is bound in as
  associated data.
- Any unknown path is served `404.html`, whose `assets/links.js` repeats the
  derivation with WebCrypto, fetches the blob, decrypts it, and redirects
  (http/https targets only). `scripts/shortlink.py` and `assets/links.js` must
  stay in step.
- **Editable:** the code is the key, so `edit` changes where a printed link or
  QR code goes without reprinting it.

**This stops casual walking; it is not secrecy.** Anyone can clone the repo and
guess codes offline. At 8 characters (40 bits) and 600k iterations, trying
every code takes on the order of a few GPU-years. That's out of reach for a
casual attacker, but a well-funded one could do it. `--length 10` makes it
about a thousand times harder. So **never shorten a URL that must stay
secret**, and remember that `rm` doesn't remove a link from git history.

Short links need JavaScript, so link previews (Slack, email) show a generic
CaRCC card rather than the destination. Clicks and QR codes work normally.

The code→URL record lives **outside** this repo, in the **"carcc.github.io
links"** sheet in the Operations folder of the CaRCC shared drive. The script
keeps it for you: every `add`, `edit`, `rm`, `alias` and `unalias` first submits
a row to a Google Form whose responses land in that sheet (pass `--what` and
`--used-in` to describe the link). If recording fails, nothing is changed. Rows
are append-only, so the latest row for a code is its current state.

The form accepts submissions without sign-in, so junk rows are possible and
harmless: the site never reads the sheet. A real row carries a `Source` (the
user and git name that ran the script) and a **Blob id** that `show CODE`
reproduces and that names a file in `s/d/`. A junk row can't fake that without a
real code. Use `--no-record` only offline, then run `record CODE` later. For a
local copy as well, `add` and `edit` take `--ledger PATH` (or
`SHORTLINK_LEDGER`), and they refuse a path inside the repo.

## Publishing

GitHub Pages deploys from the root of the `main` branch. `.nojekyll` turns off
Jekyll processing. There is no build step.
