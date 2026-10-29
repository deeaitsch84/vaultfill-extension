// node --test test/*.mjs
// E2E part needs a throwaway Vaultwarden + the official bw CLI (which insists on HTTPS):
//   openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=localhost -addext subjectAltName=DNS:localhost -keyout ssl/key.pem -out ssl/cert.pem
//   docker run -d --name vw-test -p 8222:80 -v $PWD/ssl:/ssl:ro -e ROCKET_TLS='{certs="/ssl/cert.pem",key="/ssl/key.pem"}' -e I_REALLY_WANT_VOLATILE_STORAGE=true vaultwarden/server
//   NODE_EXTRA_CA_CERTS=ssl/cert.pem VW_URL=https://localhost:8222 npm test
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as v from '../vault.js';

test('uriMatches', () => {
  const page = 'https://login.example.com/signin?x=1';
  assert.ok(v.uriMatches('https://example.com', null, page));
  assert.ok(v.uriMatches('example.com', 0, page));
  assert.ok(!v.uriMatches('https://example.org', 0, page));
  assert.ok(!v.uriMatches('https://evil-example.com', 0, page));
  assert.ok(!v.uriMatches('https://example.com', 1, page));
  assert.ok(v.uriMatches('https://login.example.com', 1, page));
  assert.ok(v.uriMatches('https://login.example.com/sign', 2, page));
  assert.ok(!v.uriMatches('https://login.example.com/x', 3, page));
  assert.ok(v.uriMatches('example\\.com/signin', 4, page));
  assert.ok(!v.uriMatches('https://example.com', 5, page));
  assert.ok(v.uriMatches('https://a.bbc.co.uk', 0, 'https://www.bbc.co.uk/'));
  assert.ok(!v.uriMatches('https://foo.co.uk', 0, 'https://bar.co.uk/'));
  assert.ok(!v.uriMatches('http://192.168.1.10', 0, 'https://10.1.1.10/'));
  assert.ok(!v.uriMatches('https://nas.local:5001', 0, 'https://nas.local:8443/'));
  assert.ok(!v.uriMatches('androidapp://com.example', 0, 'https://example.com/'));
  assert.ok(!v.uriMatches('https://example.com', 0, undefined));
  assert.ok(!v.uriMatches('https://example.com', 2, undefined));
});

test('PIN wrap round-trip', async () => {
  const userKey = v.toKey(crypto.getRandomValues(new Uint8Array(64)));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const wrapped = await v.encrypt(v.keyBytes(userKey), await v.pinKey('4711', salt));
  assert.deepEqual(await v.decrypt(wrapped, await v.pinKey('4711', salt)), v.keyBytes(userKey));
  await assert.rejects(v.decrypt(wrapped, await v.pinKey('4712', salt)), /MAC/);
});

test('totp (RFC 6238 vectors)', async () => {
  const b32 = (s) => { const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = ''; for (const c of Buffer.from(s)) bits += c.toString(2).padStart(8, '0'); return bits.match(/.{1,5}/g).map((b) => a[parseInt(b.padEnd(5, '0'), 2)]).join(''); };
  const sha1 = b32('12345678901234567890'), sha256 = b32('12345678901234567890123456789012'), sha512 = b32('1234567890123456789012345678901234567890123456789012345678901234');
  assert.equal((await v.totp(`otpauth://totp/x?secret=${sha1}&digits=8`, 59e3)).code, '94287082');
  assert.equal((await v.totp(`otpauth://totp/x?secret=${sha256}&digits=8&algorithm=SHA256`, 59e3)).code, '46119246');
  assert.equal((await v.totp(`otpauth://totp/x?secret=${sha512}&digits=8&algorithm=SHA512`, 1111111109e3)).code, '25091201');
  assert.equal((await v.totp(sha1.toLowerCase(), 1234567890e3)).code, '005924');
  assert.equal((await v.totp(sha1, 59e3)).remaining, 1);
  await assert.rejects(v.totp('not base32!'), /TOTP/);
});

test('isWeak', () => {
  for (const pw of ['', 'short', 'password123!', 'aaaaaaaaaaaaaaaa', 'Sommer2024', '1234567890ab']) assert.ok(v.isWeak(pw), pw);
  for (const pw of ['correct horse battery staple', 'Xk9#mP2$vL7@qR4!', 'tY8u-Jq3w-Zp5n-Rk2m']) assert.ok(!v.isWeak(pw), pw);
});

// --- E2E against a real server -------------------------------------------------------
const server = process.env.VW_URL;

async function register(email, password, kdf) {
  const mk = await v.makeMasterKey(password, email, kdf);
  const userKey = v.toKey(crypto.getRandomValues(new Uint8Array(64)));
  const rsa = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-1' }, true, ['encrypt', 'decrypt']);
  const post = (path, body) => fetch(`${server}/identity/accounts/register${path}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  // Without a mail server Vaultwarden returns the verification token directly.
  const emailVerificationToken = await (await post('/send-verification-email', { email, name: 'test', receiveMarketingEmails: false })).text();
  const r = await post('/finish', {
    email, emailVerificationToken, masterPasswordHash: await v.masterPasswordHash(mk, password),
    userSymmetricKey: await v.encrypt(v.keyBytes(userKey), await v.stretch(mk)), ...kdf,
    userAsymmetricKeys: {
      publicKey: v.b64(new Uint8Array(await crypto.subtle.exportKey('spki', rsa.publicKey))),
      encryptedPrivateKey: await v.encrypt(new Uint8Array(await crypto.subtle.exportKey('pkcs8', rsa.privateKey)), userKey),
    },
  });
  assert.ok(r.ok, `register: ${r.status} ${await r.text()}`);
}

// Official CLI = independent implementation: it must accept our registration and its items must decrypt with our code.
function bwLogin(email, password) {
  const env = { ...process.env, BITWARDENCLI_APPDATA_DIR: mkdtempSync(join(tmpdir(), 'bw-')), BW_PASSWORD: password };
  const bw = (...a) => execFileSync('bw', a, { env, encoding: 'utf8' }).trim();
  bw('config', 'server', server);
  env.BW_SESSION = bw('login', email, '--passwordenv', 'BW_PASSWORD', '--raw');
  return bw;
}

for (const [label, kdf] of [
  ['pbkdf2', { kdf: 0, kdfIterations: 600000 }],
  ['argon2id', { kdf: 1, kdfIterations: 3, kdfMemory: 64, kdfParallelism: 4 }],
]) {
  test(`e2e ${label}`, { skip: !server && 'VW_URL not set' }, async () => {
    const email = `t-${label}-${Date.now()}@example.com`, password = 'correct horse battery staple';
    await register(email, password, kdf);
    const bw = bwLogin(email, password);
    bw('create', 'item', Buffer.from(JSON.stringify({
      type: 1, name: 'Example', notes: 'keep me', favorite: true,
      fields: [{ name: 'pin', value: '1234', type: 1 }],
      login: { username: 'alice', password: 's3cr3t-ÄÖü', totp: 'JBSWY3DPEHPK3PXP', uris: [{ uri: 'https://example.com', match: null }] },
    })).toString('base64'));

    const pre = await v.prelogin(server, email);
    assert.equal(pre.kdf, kdf.kdf);
    const mk = await v.makeMasterKey(password, email, pre);
    const t = await v.token(server, {
      grant_type: 'password', username: email, password: await v.masterPasswordHash(mk, password),
      scope: 'api offline_access', client_id: 'browser', deviceType: '2', deviceIdentifier: crypto.randomUUID(), deviceName: 'chrome',
    });
    const userKey = v.toKey(await v.decrypt(t.key, await v.stretch(mk)));
    const vault = await v.sync(server, t.access_token);
    const state = await v.decryptVault(vault, userKey);
    assert.deepEqual(state.index.map(({ name, username }) => ({ name, username })), [{ name: 'Example', username: 'alice' }]);
    assert.ok(v.uriMatches(state.index[0].uris[0].uri, state.index[0].uris[0].match, 'https://www.example.com/login'));
    const c = vault.ciphers[0];
    assert.equal(await v.decryptStr(c.login.password, await v.itemKey(c, state)), 's3cr3t-ÄÖü');

    // live-sync hub: after a change the server must push a non-ping MessagePack frame
    const ws = new WebSocket(`${server.replace(/^http/, 'ws')}/notifications/hub?access_token=${t.access_token}`);
    ws.binaryType = 'arraybuffer';
    const pushed = new Promise((resolve) => {
      ws.onmessage = ({ data }) => {
        const b = new Uint8Array(data);
        if (!(b.length === 3 && ((b[0] === 0x7b && b[1] === 0x7d) || (b[1] === 0x91 && b[2] === 0x06)))) resolve(b);
      };
    });
    await new Promise((r) => { ws.onopen = r; });
    ws.send('{"protocol":"messagepack","version":1}\x1e');
    await new Promise((r) => setTimeout(r, 300));

    // addUri must keep every other field (checked through the official CLI)
    await v.addUri(server, t.access_token, c.id, 'https://other.example.org', await v.itemKey(c, state), vault.profile.id);
    assert.ok((await Promise.race([pushed, new Promise((r) => setTimeout(r, 5000))]))?.length > 3, 'no hub push');
    ws.close();
    bw('sync');
    const item = JSON.parse(bw('get', 'item', c.id));
    assert.deepEqual(item.login.uris.map((u) => u.uri), ['https://example.com', 'https://other.example.org']);
    assert.equal(item.notes, 'keep me');
    assert.equal(item.favorite, true);
    assert.equal(item.fields[0].value, '1234');
    assert.equal(item.login.totp, 'JBSWY3DPEHPK3PXP');
    assert.equal(item.login.password, 's3cr3t-ÄÖü');

    await assert.rejects(v.decrypt(vault.profile.key, await v.stretch(await v.makeMasterKey('wrong', email, pre))), /MAC/);
  });
}
