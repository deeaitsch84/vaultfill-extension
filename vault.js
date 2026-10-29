// Bitwarden/Vaultwarden protocol: KDF, EncString crypto, login, sync, URI matching.
// Pure functions (fetch + WebCrypto only) so they run in the service worker and in Node tests.
import './lib/argon2.umd.min.js'; // hash-wasm 4.12.0, sets globalThis.hashwasm
import psl from './lib/psl.js';

const te = new TextEncoder(), td = new TextDecoder();
export const b64 = (bytes) => btoa(Array.from(bytes, (c) => String.fromCharCode(c)).join(''));
export const b64url = (bytes) => b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const concat = (a, b) => { const r = new Uint8Array(a.length + b.length); r.set(a); r.set(b, a.length); return r; };

// Vaultwarden answers PascalCase or camelCase depending on version; normalize to camelCase.
const camel = (o) => Array.isArray(o) ? o.map(camel)
  : o && typeof o === 'object' ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k.charAt(0).toLowerCase() + k.slice(1), camel(v)]))
  : o;

// Symmetric key = { enc, mac } (32 bytes each), serialized as 64 raw bytes.
export const toKey = (raw) => ({ enc: raw.slice(0, 32), mac: raw.slice(32, 64) });
export const keyBytes = (k) => concat(k.enc, k.mac);

async function pbkdf2(password, salt, iterations) {
  const k = await crypto.subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, k, 256));
}

export async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}

export async function makeMasterKey(password, email, kdf) {
  const salt = te.encode(email.trim().toLowerCase());
  if (kdf.kdf === 1) {
    return globalThis.hashwasm.argon2id({
      password, salt: new Uint8Array(await crypto.subtle.digest('SHA-256', salt)),
      iterations: kdf.kdfIterations, memorySize: kdf.kdfMemory * 1024, parallelism: kdf.kdfParallelism,
      hashLength: 32, outputType: 'binary',
    });
  }
  return pbkdf2(te.encode(password), salt, kdf.kdfIterations);
}

// Wrapping key for the PIN/Touch-ID copies of the user key.
export const pinKey = async (pin, salt) => stretch(await pbkdf2(te.encode(pin), salt, 100000));

export const masterPasswordHash = async (masterKey, password) => b64(await pbkdf2(masterKey, te.encode(password), 1));

// HKDF-Expand (single block, no extract step), as Bitwarden does it.
export const stretch = async (masterKey) => ({
  enc: await hmac(masterKey, te.encode('enc\x01')),
  mac: await hmac(masterKey, te.encode('mac\x01')),
});

// shortcut: only EncString type 2 (AES-CBC-256 + HMAC); type 0 exists only on pre-2018 accounts.
export async function decrypt(encString, key) {
  const dot = encString.indexOf('.');
  const type = +encString.slice(0, dot);
  if (type !== 2) throw new Error(`Unsupported EncString type ${type}`);
  const [iv, ct, mac] = encString.slice(dot + 1).split('|').map(unb64);
  const want = await hmac(key.mac, concat(iv, ct));
  if (want.length !== mac.length || want.some((b, i) => b !== mac[i])) throw new Error('MAC mismatch');
  const k = await crypto.subtle.importKey('raw', key.enc, 'AES-CBC', false, ['decrypt']);
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-CBC', iv }, k, ct));
}

export const decryptStr = async (s, key) => s ? td.decode(await decrypt(s, key)) : '';

export async function encrypt(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const k = await crypto.subtle.importKey('raw', key.enc, 'AES-CBC', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv }, k, data));
  return `2.${b64(iv)}|${b64(ct)}|${b64(await hmac(key.mac, concat(iv, ct)))}`;
}

export const encryptStr = (s, key) => encrypt(te.encode(s), key);

async function request(url, init) {
  const r = await fetch(url, init);
  const j = camel(await r.json().catch(() => ({})));
  if (!r.ok) {
    const msg = j.errorModel?.message || j.error_description || j.message || `HTTP ${r.status}`;
    throw Object.assign(new Error(msg), { data: j });
  }
  return j;
}

// Local/LAN hosts may use plain http (dev servers, home NAS); everything else must be https.
const LOCAL_HOST = /^(localhost|.+\.(local|lan|internal|home\.arpa)|127(\.\d+){3}|10(\.\d+){3}|192\.168(\.\d+){2}|172\.(1[6-9]|2\d|3[01])(\.\d+){2}|\[::1\])$/i;

// Normalizes what the user typed: adds https://, prefers https over a typed http:// (some proxies answer
// plain http with 404 instead of redirecting), follows redirects (moved host, path prefix) via /api/config.
export async function resolveServer(input) {
  const url = input.trim().replace(/\/+$/, '');
  const https = /^https:\/\//i.test(url) ? url : `https://${url.replace(/^http:\/\//i, '')}`;
  const candidates = /^http:\/\//i.test(url) && LOCAL_HOST.test(new URL(url).hostname) ? [https, url] : [https];
  for (const c of candidates) {
    const r = await fetch(`${c}/api/config`).catch(() => null);
    if (!r?.ok) continue;
    const final = new URL(r.url);
    if (final.protocol !== 'https:' && !LOCAL_HOST.test(final.hostname)) throw new Error('Server redirects to unencrypted http – aborted');
    return r.url.replace(/\/api\/config$/, '');
  }
  throw new Error(`No Vaultwarden reachable at ${url} (https only; http only for local servers)`);
}

// A malicious server could hand out a weak KDF to make the master password hash cheap to crack:
// enforce sane bounds, and never accept weaker settings than seen before for this account (pinned).
export function checkKdf(k, pinned) {
  const ok = k.kdf === 0 ? k.kdfIterations >= 100_000 && k.kdfIterations <= 2_000_000
    : k.kdf === 1 ? k.kdfIterations >= 2 && k.kdfIterations <= 10 && k.kdfMemory >= 16 && k.kdfMemory <= 1024 && k.kdfParallelism >= 1 && k.kdfParallelism <= 16
      : false;
  if (!ok) throw new Error('Insecure or invalid KDF settings from the server – sign-in aborted');
  const weaker = pinned && (k.kdf !== pinned.kdf || k.kdfIterations < pinned.kdfIterations || (k.kdfMemory || 0) < (pinned.kdfMemory || 0));
  if (weaker) throw new Error('The server reports weaker KDF settings than at the last sign-in – sign-in aborted');
}

export const prelogin = (server, email) => request(`${server}/identity/accounts/prelogin`, {
  method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }),
});

export const token = (server, form) => request(`${server}/identity/connect/token`, {
  method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(form),
});

// Keep only what autofill needs, so chrome.storage.local stays small.
export async function sync(server, accessToken) {
  const j = await request(`${server}/api/sync?excludeDomains=true`, { headers: { Authorization: `Bearer ${accessToken}` } });
  return {
    profile: {
      id: j.profile.id, key: j.profile.key, privateKey: j.profile.privateKey,
      organizations: (j.profile.organizations || []).map(({ id, key }) => ({ id, key })),
    },
    ciphers: j.ciphers.filter((c) => c.type === 1 && !c.deletedDate)
      .map(({ id, organizationId, key, name, login }) => ({ id, organizationId, key, name, login })),
  };
}

// Read-modify-write on the full server copy so no other field gets lost; the server rejects it if the item changed meanwhile.
async function editLogin(server, accessToken, id, userId, mutate) {
  const auth = { Authorization: `Bearer ${accessToken}` };
  const c = await request(`${server}/api/ciphers/${id}`, { headers: auth });
  await mutate(c);
  return request(`${server}/api/ciphers/${id}`, {
    method: 'PUT', headers: { ...auth, 'Content-Type': 'application/json' },
    body: JSON.stringify({ ...c, encryptedFor: userId, lastKnownRevisionDate: c.revisionDate }),
  });
}

export const addUri = (server, accessToken, id, uri, key, userId) => editLogin(server, accessToken, id, userId, async (c) => {
  c.login.uris = [...(c.login.uris || []), { uri: await encryptStr(uri, key), match: null }];
});

// New password; the old (still encrypted) one moves into the password history like Bitwarden clients do.
export const updatePassword = (server, accessToken, id, password, key, userId) => editLogin(server, accessToken, id, userId, async (c) => {
  const now = new Date().toISOString();
  if (c.login.password) c.passwordHistory = [{ password: c.login.password, lastUsedDate: now }, ...(c.passwordHistory || [])].slice(0, 5);
  c.login.password = await encryptStr(password, key);
  c.login.passwordRevisionDate = now;
});

// New personal login. Fields are encrypted with the user key (no per-item key, like older clients do).
export async function createLogin(server, accessToken, { name, username, password, uri }, userKey, userId) {
  const enc = (s) => s ? encryptStr(s, userKey) : null;
  return request(`${server}/api/ciphers`, {
    method: 'POST', headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      type: 1, name: await enc(name), notes: null, favorite: false, reprompt: 0, folderId: null, organizationId: null, encryptedFor: userId,
      login: { username: await enc(username), password: await enc(password), totp: null, uris: uri ? [{ uri: await enc(uri), match: null }] : [] },
    }),
  });
}

// --- TOTP (RFC 6238), secret as base32 or otpauth:// URI ------------------------------------

export async function totp(secret, now = Date.now()) {
  let key = secret.trim(), algo = 'SHA-1', digits = 6, period = 30;
  if (/^otpauth:/i.test(key)) {
    const u = new URL(key);
    key = u.searchParams.get('secret') || '';
    algo = { SHA256: 'SHA-256', SHA512: 'SHA-512' }[(u.searchParams.get('algorithm') || '').toUpperCase()] || 'SHA-1';
    digits = +u.searchParams.get('digits') || 6;
    period = +u.searchParams.get('period') || 30;
  }
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const ch of key.toUpperCase().replace(/[\s=-]/g, '')) {
    const i = alphabet.indexOf(ch);
    if (i < 0) throw new Error('Invalid TOTP secret');
    bits += i.toString(2).padStart(5, '0');
  }
  const raw = Uint8Array.from(bits.match(/.{8}/g) || [], (b) => parseInt(b, 2));
  const counter = new DataView(new ArrayBuffer(8));
  counter.setBigUint64(0, BigInt(Math.floor(now / 1000 / period)));
  const k = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: algo }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', k, counter.buffer));
  const o = h[h.length - 1] & 15;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return { code: String(bin % 10 ** digits).padStart(digits, '0'), remaining: period - Math.floor(now / 1000) % period };
}

// --- password health ------------------------------------------------------------------------

// shortcut: entropy estimate from length × character classes plus a few obvious patterns; use zxcvbn if it misjudges.
export function isWeak(pw) {
  if (!pw || pw.length < 10) return true;
  const pool = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].reduce((n, re, i) => n + (re.test(pw) ? [26, 26, 10, 33][i] : 0), 0);
  const unique = new Set(pw).size;
  const bits = Math.log2(pool) * Math.min(pw.length, unique * 2);
  return bits < 50 || /^(.)\1+$/.test(pw) || /(password|passwort|qwert|12345|abcdef)/i.test(pw)
    || (pw.length < 14 && /^[A-Za-zäöüÄÖÜß]+[0-9]+[^A-Za-z0-9]?$/.test(pw)); // "Sommer2024", "Hamburg1!"

}

// Have I Been Pwned range API (k-anonymity): only the first 5 hex chars of the SHA-1 leave the machine.
export async function pwnedCount(pw) {
  const hex = [...new Uint8Array(await crypto.subtle.digest('SHA-1', te.encode(pw)))].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  const r = await fetch(`https://api.pwnedpasswords.com/range/${hex.slice(0, 5)}`, { headers: { 'Add-Padding': 'true' } });
  if (!r.ok) throw new Error(`HIBP: HTTP ${r.status}`);
  const line = (await r.text()).split('\n').find((l) => l.startsWith(hex.slice(5)));
  return line ? +line.split(':')[1] : 0;
}

// Returns session state: user key, org keys and a decrypted index (no passwords).
export async function decryptVault(vault, userKey) {
  const orgKeys = {};
  if (vault.profile.organizations.length) {
    const pk = await crypto.subtle.importKey('pkcs8', await decrypt(vault.profile.privateKey, userKey),
      { name: 'RSA-OAEP', hash: 'SHA-1' }, false, ['decrypt']);
    for (const o of vault.profile.organizations) {
      // shortcut: assumes org key type 4 (RSA-OAEP-SHA1), the only one Bitwarden clients emit today.
      const ct = unb64(o.key.slice(o.key.indexOf('.') + 1).split('|')[0]);
      orgKeys[o.id] = b64(new Uint8Array(await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, pk, ct)));
    }
  }
  const state = { userKey: b64(keyBytes(userKey)), orgKeys, index: [] };
  for (const c of vault.ciphers) {
    try {
      const k = await itemKey(c, state);
      state.index.push({
        id: c.id,
        name: await decryptStr(c.name, k),
        username: await decryptStr(c.login?.username, k),
        uris: await Promise.all((c.login?.uris || []).map(async (u) => ({ uri: await decryptStr(u.uri, k), match: u.match }))),
        totp: !!c.login?.totp,
      });
    } catch (e) {
      console.warn('skip cipher', c.id, e.message);
    }
  }
  return state;
}

export async function itemKey(cipher, state) {
  const k = toKey(unb64(cipher.organizationId ? state.orgKeys[cipher.organizationId] : state.userKey));
  return cipher.key ? toKey(await decrypt(cipher.key, k)) : k;
}

// Public Suffix List (incl. private suffixes like github.io): registrable domain = public suffix + one label.
const SUFFIX = new Set(), WILDCARD = new Set(), EXCEPTION = new Set();
for (const r of psl.split('\n')) {
  if (r.startsWith('!')) EXCEPTION.add(r.slice(1));
  else if (r.startsWith('*.')) WILDCARD.add(r.slice(2));
  else SUFFIX.add(r);
}

// null when the host itself is a public suffix (e.g. "github.io")
export function registrableDomain(host) {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.');
  for (let i = 0; i < labels.length; i++) { // longest suffix first
    const s = labels.slice(i).join('.');
    if (EXCEPTION.has(s)) return s;
    if (SUFFIX.has(s) || WILDCARD.has(labels.slice(i + 1).join('.'))) return i > 0 ? labels.slice(i - 1).join('.') : null;
  }
  return labels.slice(-2).join('.'); // unlisted TLD: default rule "*"
}

const baseDomain = (host) => /^[\d.]+$|:/.test(host) ? host : registrableDomain(host) ?? host;
const parseUri = (uri) => { try { return new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(uri) ? uri : `https://${uri}`); } catch { return null; } };

// match: 0 base domain (default), 1 host, 2 starts with, 3 exact, 4 regex, 5 never
export function uriMatches(uri, match, pageUrl) {
  if (!uri || !pageUrl) return false; // Chrome hides the URL of chrome:// and other non-permitted tabs
  let p;
  try { p = new URL(pageUrl); } catch { return false; }
  switch (match ?? 0) {
    case 1: case 0: {
      const u = parseUri(uri);
      if (!u || !/^https?:$/.test(u.protocol) || !/^https?:$/.test(p.protocol)) return false;
      if (u.protocol === 'https:' && p.protocol !== 'https:') return false; // never offer https logins on an http page
      if (u.port !== p.port) return false; // other port = other service
      return match === 1 ? u.hostname === p.hostname : baseDomain(u.hostname) === baseDomain(p.hostname);
    }
    case 2: { // same origin, then path prefix (a raw string prefix would let bank.com match bank.com.evil.net)
      const u = parseUri(uri);
      return !!u && u.origin === p.origin && p.href.startsWith(u.href);
    }
    case 3: return pageUrl === uri;
    case 4: try { return new RegExp(uri, 'i').test(pageUrl); } catch { return false; }
    default: return false;
  }
}
