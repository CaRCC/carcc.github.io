// carcc.github.io link resolver, loaded by 404.html (every unknown path lands there).
//   /s/CODE        opaque short link: derive (id, key) from CODE, fetch s/d/<id>.json, decrypt, go.
//   /NAME/rest     vanity alias from aliases.json; deep links keep `rest` when the target ends in "/".
// Mirrors scripts/shortlink.py derive()/encrypt(); keep SALT, ITERATIONS and the blob format in step.
(function () {
  var ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  var SALT = 'carcc.github.io/s/v1';
  var ITERATIONS = 600000;
  var enc = new TextEncoder();

  function say(title, text) {
    var h = document.getElementById('status-title'), p = document.getElementById('status-text');
    if (h) h.textContent = title;
    if (p) p.textContent = text;
  }
  function notFound() { say('Page not found', "That page doesn't exist here."); }
  function go(url) {
    if (!/^https?:\/\//i.test(url)) return notFound();  // never follow javascript: or data: URLs
    location.replace(url);
  }
  function b64(s) { return Uint8Array.from(atob(s), function (c) { return c.charCodeAt(0); }); }
  function hex(buf) {
    return Array.from(new Uint8Array(buf), function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }
  function normalize(code) {
    var c = code.toUpperCase().replace(/-/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
    for (var i = 0; i < c.length; i++) if (ALPHABET.indexOf(c[i]) < 0) return null;
    return c;
  }

  async function resolveShort(raw) {
    var code = normalize(raw);
    if (!code || !(crypto && crypto.subtle)) return notFound();
    say('Opening link…', '');
    var s = crypto.subtle;
    var base = await s.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveBits']);
    var master = await s.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(SALT),
                                      iterations: ITERATIONS }, base, 256);
    var mac = await s.importKey('raw', master, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    var id = hex(await s.sign('HMAC', mac, enc.encode('id'))).slice(0, 24);
    var key = await s.importKey('raw', await s.sign('HMAC', mac, enc.encode('key')), 'AES-GCM', false, ['decrypt']);
    var r = await fetch('/s/d/' + id + '.json', { cache: 'no-cache' });
    if (!r.ok) return notFound();
    var blob = await r.json();
    var pt = await s.decrypt({ name: 'AES-GCM', iv: b64(blob.iv), additionalData: enc.encode(id) }, key, b64(blob.ct));
    go(JSON.parse(new TextDecoder().decode(pt)).u);
  }

  async function resolveAlias(name, rest) {
    var r = await fetch('/aliases.json', { cache: 'no-cache' });
    var target = r.ok && (await r.json())[name.toLowerCase()];
    if (!target) return notFound();
    var tail = target.slice(-1) === '/' ? rest.replace(/^\//, '') : '';
    go(target + tail + location.search + location.hash);
  }

  var path = location.pathname, m;
  var run = (m = path.match(/^\/s\/([0-9A-Za-z-]+)\/?$/i)) ? resolveShort(m[1])
          : (m = path.match(/^\/([^\/]+)(\/.*)?$/)) ? resolveAlias(m[1], m[2] || '')
          : Promise.resolve(notFound());
  run.catch(notFound);
})();
