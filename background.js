// State holder. Encrypted vault + tokens live in storage.local; the decrypted user key and
// index (names, usernames, URIs — no passwords) live in storage.session (RAM, gone on browser exit).
import * as v from './vault.js';

const local = chrome.storage.local, session = chrome.storage.session;
const IDLE_LOCK_SECONDS = 30 * 60;
const PIN_MAX_TRIES = 5;

async function accessToken() {
  const s = await local.get(['server', 'accessToken', 'tokenExp', 'refreshToken']);
  if (s.accessToken && Date.now() < s.tokenExp - 60e3) return s.accessToken;
  const t = await v.token(s.server, { grant_type: 'refresh_token', client_id: 'browser', refresh_token: s.refreshToken });
  await local.set({ accessToken: t.access_token, tokenExp: Date.now() + t.expires_in * 1000, refreshToken: t.refresh_token || s.refreshToken });
  return t.access_token;
}

async function sync() {
  const { server } = await local.get('server');
  const vault = await v.sync(server, await accessToken());
  await local.set({ vault, lastSync: Date.now() });
  const { userKey } = await session.get('userKey');
  if (userKey) await session.set(await v.decryptVault(vault, v.toKey(v.unb64(userKey))));
}

const sessionUserKey = async () => {
  const { userKey } = await session.get('userKey');
  if (!userKey) throw new Error('Vault locked');
  return v.toKey(v.unb64(userKey));
};

// Every unlock path ends here. Also re-arms the PIN for this browser session.
async function openVault(userKey) {
  const { vault, pinEnc, pinSalt } = await local.get(['vault', 'pinEnc', 'pinSalt']);
  await session.set(await v.decryptVault(vault, userKey));
  if (pinEnc) await armPin(await v.decryptStr(pinEnc, userKey), userKey, pinSalt);
}

const armPin = async (pin, userKey, salt) =>
  session.set({ pinWrapped: await v.encrypt(v.keyBytes(userKey), await v.pinKey(pin, v.unb64(salt))), pinTries: 0 });

// --- login (password or SSO) -----------------------------------------------------------

// p = { server, email, kdf, mk (master key, base64) }; grant = password or SSO authorization_code fields.
// If the server wants 2FA, the attempt is parked in storage.session and retried with the code (SSO codes are reusable).
async function finishLogin(p, grant, { totp, provider } = {}) {
  const { deviceId = crypto.randomUUID(), twoFactorRemember } = await local.get(['deviceId', 'twoFactorRemember']);
  const form = { ...grant, scope: 'api offline_access', client_id: 'browser', deviceType: '2', deviceIdentifier: deviceId, deviceName: 'chrome' };
  if (totp) Object.assign(form, { twoFactorToken: totp.replace(/\s/g, ''), twoFactorProvider: String(provider), twoFactorRemember: '1' });
  else if (twoFactorRemember) Object.assign(form, { twoFactorToken: twoFactorRemember, twoFactorProvider: '5' });

  let t;
  try {
    t = await v.token(p.server, form);
  } catch (e) {
    const providers = (e.data?.twoFactorProviders || []).map(Number);
    if (!providers.length) throw e;
    // 0 = authenticator app, 1 = email; hardware keys / WebAuthn are not supported here.
    const prov = [0, 1].find((x) => providers.includes(x));
    if (prov === undefined) throw new Error('Only TOTP or e-mail 2FA is supported');
    await session.set({ pending: { ...p, grant, provider: prov } });
    return { needTotp: true, provider: prov };
  }
  const userKey = v.toKey(await v.decrypt(t.key, await v.stretch(v.unb64(p.mk))));
  await local.set({
    server: p.server, email: p.email, kdf: p.kdf, deviceId, accessToken: t.access_token, tokenExp: Date.now() + t.expires_in * 1000,
    refreshToken: t.refresh_token, twoFactorRemember: t.twoFactorToken || twoFactorRemember,
  });
  await session.remove('pending');
  const { kdfPins = {} } = await local.get('kdfPins');
  await local.set({ kdfPins: { ...kdfPins, [`${p.server}|${p.email}`]: p.kdf } });
  await sync();
  await openVault(userKey);
  connectHub();
  return {};
}

async function login({ server, email, password, totp }) {
  const { pending } = await session.get('pending');
  if (totp && pending) return finishLogin(pending, pending.grant, { totp, provider: pending.provider });
  server = await v.resolveServer(server);
  email = email.trim().toLowerCase();
  const kdf = await v.prelogin(server, email);
  const { kdfPins = {} } = await local.get('kdfPins');
  v.checkKdf(kdf, kdfPins[`${server}|${email}`]);
  const mk = await v.makeMasterKey(password, email, kdf);
  const p = { server, email, kdf, mk: v.b64(mk) };
  try {
    return await finishLogin(p, { grant_type: 'password', username: email, password: await v.masterPasswordHash(mk, password) });
  } catch (e) {
    if (!/SSO sign-in is required/i.test(e.message)) throw e;
  }
  return startSso(p);
}

// SSO: Vaultwarden does the OIDC dance with the IdP and finally redirects the tab to
// <server>/sso-connector.html?code=…&state=… — we catch that URL in tabs.onUpdated.
async function startSso(p) {
  const rand = () => v.b64url(crypto.getRandomValues(new Uint8Array(32)));
  const verifier = rand(), state = rand(), redirect = `${p.server}/sso-connector.html`;
  const challenge = v.b64url(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))));
  const url = `${p.server}/identity/connect/authorize?${new URLSearchParams({
    client_id: 'browser', redirect_uri: redirect, response_type: 'code', response_mode: 'query', scope: 'api offline_access',
    state, code_challenge: challenge, code_challenge_method: 'S256',
  })}`;
  const tab = await chrome.tabs.create({ url });
  await session.set({ sso: { ...p, verifier, state, redirect, tabId: tab.id } });
  return { sso: true };
}

chrome.tabs.onUpdated.addListener(async (tabId, { url }) => {
  if (!url) return;
  const { sso } = await session.get('sso');
  if (!sso || tabId !== sso.tabId || !url.startsWith(sso.redirect)) return;
  await session.remove('sso');
  chrome.tabs.remove(tabId);
  const q = new URL(url).searchParams;
  let res;
  try {
    if (q.get('state') !== sso.state) throw new Error('SSO: state mismatch');
    res = await finishLogin(sso, { grant_type: 'authorization_code', code: q.get('code'), code_verifier: sso.verifier, redirect_uri: sso.redirect });
  } catch (e) {
    res = { error: e.message };
  }
  if (res.error) await session.set({ loginError: res.error });
  chrome.action.openPopup().catch(() => {}); // show result / 2FA prompt
});

// --- unlock: PIN, master password, Touch ID --------------------------------------------

// One field takes PIN or master password: the PIN is tried first (cheap), then the master password.
async function unlock({ password }) {
  const { email, kdf, vault, pinSalt } = await local.get(['email', 'kdf', 'vault', 'pinSalt']);
  const { pinWrapped, pinTries = 0 } = await session.get(['pinWrapped', 'pinTries']);
  let userKey;
  if (pinWrapped) {
    try { userKey = v.toKey(await v.decrypt(pinWrapped, await v.pinKey(password, v.unb64(pinSalt)))); } catch {}
  }
  if (!userKey) {
    try { userKey = v.toKey(await v.decrypt(vault.profile.key, await v.stretch(await v.makeMasterKey(password, email, kdf)))); }
    catch {
      if (pinWrapped && pinTries + 1 >= PIN_MAX_TRIES) await session.remove(['pinWrapped', 'pinTries']);
      else if (pinWrapped) await session.set({ pinTries: pinTries + 1 });
      throw new Error(pinWrapped ? 'Wrong PIN or master password' : 'Wrong master password');
    }
  }
  await openVault(userKey);
  sync().catch((e) => console.warn('sync', e)); // refresh in background, unlock must stay fast
  return {};
}

async function setPin({ pin }) {
  if (!/^\d{4,}$/.test(pin)) throw new Error('PIN: at least 4 digits');
  const userKey = await sessionUserKey(), salt = v.b64(crypto.getRandomValues(new Uint8Array(16)));
  await local.set({ pinEnc: await v.encryptStr(pin, userKey), pinSalt: salt });
  await armPin(pin, userKey, salt);
  return {};
}

// Touch ID: popup.js runs WebAuthn with the PRF extension and hands us the 32-byte PRF output.
// That secret wraps the user key; the wrapped copy may live on disk because the secret never does.
async function enrollTouchId({ credId, salt, secret }) {
  const wrapped = await v.encrypt(v.keyBytes(await sessionUserKey()), await v.stretch(v.unb64(secret)));
  await local.set({ touchId: { credId, salt, wrapped } });
  return {};
}

async function unlockTouchId({ secret }) {
  const { touchId } = await local.get('touchId');
  let userKey;
  try { userKey = v.toKey(await v.decrypt(touchId.wrapped, await v.stretch(v.unb64(secret)))); }
  catch { throw new Error('Touch ID no longer matches – please set it up again'); }
  await openVault(userKey);
  sync().catch((e) => console.warn('sync', e));
  return {};
}

// PIN stays armed; captured passwords (offers) and remembered usernames go with the key
const lock = async () => {
  const parked = Object.keys(await session.get(null)).filter((k) => /^(offer|step):/.test(k));
  await session.remove(['userKey', 'orgKeys', 'index', 'pending', 'sso', ...parked]);
};

// Prefer the action popup (Touch ID starts there by itself); a window only if Chrome refuses to open it.
async function openUnlock() {
  try { return await chrome.action.openPopup(); } catch (e) { console.warn('openPopup', e); }
  const { unlockWin } = await session.get('unlockWin');
  if (unlockWin) {
    try { return await chrome.windows.update(unlockWin, { focused: true }); } catch {}
  }
  const w = await chrome.windows.create({ url: 'popup.html?win', type: 'popup', width: 460, height: 440 });
  await session.set({ unlockWin: w.id });
}

async function status() {
  const { email, server, vault, lastSync, touchId, pinEnc } = await local.get(['email', 'server', 'vault', 'lastSync', 'touchId', 'pinEnc']);
  const { index, pending, loginError, pinWrapped } = await session.get(['index', 'pending', 'loginError', 'pinWrapped']);
  if (loginError) await session.remove('loginError');
  return {
    loggedIn: !!vault, unlocked: !!index, email, server, count: index?.length, lastSync, pendingTotp: pending?.provider, loginError,
    touchId: touchId && { credId: touchId.credId, salt: touchId.salt }, pin: !!pinEnc, pinArmed: !!pinWrapped,
  };
}

// --- suggestions & filling -------------------------------------------------------------

const matching = (index, url) => index.filter((e) => e.uris.some((u) => v.uriMatches(u.uri, u.match, url)));

async function byLastUsed(items) {
  const { lastUsed = {} } = await local.get('lastUsed');
  return items.toSorted((a, b) => (lastUsed[b.id] || 0) - (lastUsed[a.id] || 0) || a.name.localeCompare(b.name));
}

async function credentials(id) {
  const s = await session.get(['userKey', 'orgKeys']);
  const { vault, lastUsed = {} } = await local.get(['vault', 'lastUsed']);
  const c = vault.ciphers.find((x) => x.id === id);
  const k = await v.itemKey(c, s);
  await local.set({ lastUsed: { ...lastUsed, [id]: Date.now() } });
  return { username: await v.decryptStr(c.login.username, k), password: await v.decryptStr(c.login.password, k) };
}

// Content scripts get only entries matching the frame they run in (sender.url, set by Chrome, not the page).
async function suggest(sender) {
  const { index } = await session.get('index');
  if (!index) return { locked: (await status()).loggedIn };
  return { items: (await byLastUsed(matching(index, sender.url))).map(({ id, name, username }) => ({ id, name, username })) };
}

async function fill({ id }, sender) {
  const { index } = await session.get('index');
  if (!index || !matching(index, sender.url).some((e) => e.id === id)) throw new Error('no match');
  return credentials(id);
}

// --- TOTP ---------------------------------------------------------------------------------

async function totpFor(id) {
  const s = await session.get(['userKey', 'orgKeys']);
  const { vault } = await local.get('vault');
  const c = vault.ciphers.find((x) => x.id === id);
  return v.totp(await v.decryptStr(c.login.totp, await v.itemKey(c, s)));
}

async function suggestTotp(sender) {
  const { index } = await session.get('index');
  if (!index) return { locked: (await status()).loggedIn };
  const hits = (await byLastUsed(matching(index, sender.url))).filter((e) => e.totp);
  return { items: await Promise.all(hits.map(async (e) => ({ id: e.id, name: e.name, username: e.username, ...(await totpFor(e.id)) }))) };
}

async function totpCode({ id }, sender) {
  const { index } = await session.get('index');
  if (!index || !matching(index, sender.url).some((e) => e.id === id && e.totp)) throw new Error('no match');
  return totpFor(id);
}

// --- save / update after a login form was submitted ----------------------------------------
// The content script reports what was typed; we compare with the vault and park an offer per tab
// (RAM only, 5 min) so the prompt survives the navigation that usually follows a login.

const OFFER_TTL = 5 * 60e3;
const sameUser = (a = '', b = '') => a.trim().toLowerCase() === b.trim().toLowerCase();
const publicOffer = (o) => o && { kind: o.id ? 'update' : 'save', name: o.name, username: o.username, host: o.host };
// Note: no update without a username match — guessing the entry let a page overwrite a stored password.

const siteOf = (url) => { try { const h = new URL(url).hostname; return v.registrableDomain(h) ?? h; } catch { return null; } };

async function stepUser({ username }, sender) {
  await session.set({ [`step:${sender.tab.id}`]: { username, site: siteOf(sender.url), ts: Date.now() } });
  return {};
}

async function captured({ username = '', password }, sender) {
  const url = new URL(sender.url);
  if (!password || !/^https?:$/.test(url.protocol)) return {};
  const { neverSave = [], vault } = await local.get(['neverSave', 'vault']);
  if (neverSave.includes(url.hostname)) return {};
  const s = await session.get(['index', 'userKey', 'orgKeys', `step:${sender.tab.id}`]);
  if (!s.index) return {}; // locked: nothing to compare against
  const step = s[`step:${sender.tab.id}`];
  if (!username && step && step.site === siteOf(sender.url) && Date.now() - step.ts < OFFER_TTL) username = step.username; // two-step login
  const candidates = matching(s.index, sender.url);
  let update;
  for (const e of candidates) {
    const c = vault.ciphers.find((x) => x.id === e.id);
    const known = await v.decryptStr(c.login.password, await v.itemKey(c, s));
    if (known === password && (!username || sameUser(e.username, username))) return {}; // nothing new
    if (username && sameUser(e.username, username)) update = e;
  }
  const offer = { id: update?.id, name: update?.name || url.hostname, username: update?.username ?? username, password, host: url.hostname, url: url.origin, ts: Date.now() };
  await session.set({ [`offer:${sender.tab.id}`]: offer });
  // a login inside an iframe: show the prompt in the page itself, not in the (small) frame
  if (sender.frameId) chrome.tabs.sendMessage(sender.tab.id, { type: 'showOffer', offer: publicOffer(offer) }, { frameId: 0 }).catch(() => {});
  return { offer: publicOffer(offer) };
}

// Offers stay bound to the site that produced them: another site in the same tab can neither show nor confirm them.
async function pendingOffer(sender) {
  const key = `offer:${sender.tab.id}`, { [key]: o } = await session.get(key);
  return { offer: o && Date.now() - o.ts < OFFER_TTL && siteOf(o.url) === siteOf(sender.url) ? publicOffer(o) : null };
}

async function offerAction({ action, name, username }, sender) {
  const key = `offer:${sender.tab.id}`, { [key]: o } = await session.get(key);
  if (!o || siteOf(o.url) !== siteOf(sender.url)) return {};
  await session.remove([key, `step:${sender.tab.id}`]);
  if (action === 'never') {
    const { neverSave = [] } = await local.get('neverSave');
    await local.set({ neverSave: [...new Set([...neverSave, o.host])] });
  }
  if (action !== 'save') return {};
  const { server, vault } = await local.get(['server', 'vault']);
  if (o.id) {
    const c = vault.ciphers.find((x) => x.id === o.id);
    await v.updatePassword(server, await accessToken(), o.id, o.password, await v.itemKey(c, await session.get(['userKey', 'orgKeys'])), vault.profile.id);
  } else {
    await v.createLogin(server, await accessToken(), { name: name?.trim() || o.name, username: username ?? o.username, password: o.password, uri: o.url }, await sessionUserKey(), vault.profile.id);
  }
  await sync();
  return {};
}

// Popup search: empty query = entries for the current tab, otherwise everything matching name/username/URI.
async function search({ q, tabId }) {
  const { index = [] } = await session.get('index');
  const { url } = await chrome.tabs.get(tabId);
  const needle = q.trim().toLowerCase();
  const hits = needle
    ? index.filter((e) => [e.name, e.username, ...e.uris.map((u) => u.uri)].some((s) => s?.toLowerCase().includes(needle)))
    : matching(index, url);
  const forTab = new Set(matching(index, url).map((e) => e.id));
  const site = (e) => e.uris.map((u) => u.uri).find((u) => /^https?:\/\//i.test(u) || !/:\/\//.test(u));
  return {
    host: url && /^https?:/.test(url) ? new URL(url).hostname : null,
    items: (await byLastUsed(hits)).slice(0, 30).map((e) => ({
      id: e.id, name: e.name, username: e.username, matches: forTab.has(e.id), site: site(e) && (/:\/\//.test(site(e)) ? site(e) : `https://${site(e)}`),
    })),
  };
}

// Explicit user choice in the popup, so the entry need not match; only the top frame gets it.
async function fillTab({ id, tabId, remember }) {
  const { url } = await chrome.tabs.get(tabId);
  const msg = { type: 'fillCred', origin: new URL(url).origin, ...(await credentials(id)) }; // receiver checks the origin: no redirect race
  await chrome.tabs.sendMessage(tabId, msg, { frameId: 0 }).catch(async () => {
    // tab predates the content script (opened before install/reload): inject and retry
    try { await injectContent(tabId); } catch { throw new Error('Cannot fill on this page'); }
    return chrome.tabs.sendMessage(tabId, msg, { frameId: 0 });
  });
  const { index } = await session.get('index');
  if (remember && !matching(index, url).some((e) => e.id === id)) {
    const { server, vault } = await local.get(['server', 'vault']);
    const c = vault.ciphers.find((x) => x.id === id);
    await v.addUri(server, await accessToken(), id, new URL(url).origin, await v.itemKey(c, await session.get(['userKey', 'orgKeys'])), vault.profile.id);
    await sync();
  }
  return {};
}

// --- live sync via Vaultwarden's SignalR hub (MessagePack) ------------------------------
// Server pushes on every vault change; we only need "something changed" → debounced sync.
// Our own ping every 20 s also keeps the MV3 service worker alive.
const PING = new Uint8Array([0x02, 0x91, 0x06]);
let ws, connecting, pingTimer, syncTimer;

async function connectHub() {
  if (ws || connecting) return; // callers overlap (worker start, login, alarm); token fetch is async
  connecting = true;
  let server, token;
  try {
    const s = await local.get(['server', 'refreshToken']);
    if (!s.refreshToken) return;
    server = s.server;
    try { token = await accessToken(); } catch { return setTimeout(connectHub, 60e3); }
  } finally { connecting = false; }
  const sock = (ws = new WebSocket(`${server.replace(/^http/, 'ws')}/notifications/hub?access_token=${encodeURIComponent(token)}`));
  sock.binaryType = 'arraybuffer';
  // handlers use their own socket: a reconnect may already have replaced the global `ws`
  sock.onopen = () => {
    sock.send('{"protocol":"messagepack","version":1}\x1e');
    pingTimer = setInterval(() => sock.readyState === WebSocket.OPEN && sock.send(PING), 20e3);
  };
  sock.onmessage = ({ data }) => {
    const b = new Uint8Array(data);
    if (b.length === 3 && ((b[0] === 0x7b && b[1] === 0x7d) || (b[1] === 0x91 && b[2] === 0x06))) return; // handshake "{}" or ping
    clearTimeout(syncTimer);
    syncTimer = setTimeout(() => sync().catch((e) => console.warn('sync', e)), 1500);
  };
  sock.onclose = () => {
    clearInterval(pingTimer);
    if (ws === sock) ws = null;
    setTimeout(connectHub, 30e3);
  };
}

// --- wiring -----------------------------------------------------------------------------

const popupOnly = {
  login, unlock, status, setPin, credentials: ({ id }) => credentials(id), enrollTouchId, unlockTouchId, search, fillTab,
  sync: async () => { await sync(); return {}; },
  lock: async () => { await lock(); return {}; },
  removePin: async () => { await local.remove(['pinEnc', 'pinSalt']); await session.remove(['pinWrapped', 'pinTries']); return {}; },
  removeTouchId: async () => { await local.remove('touchId'); return {}; },
  logout: async () => {
    const { deviceId, kdfPins } = await local.get(['deviceId', 'kdfPins']);
    await local.clear(); await session.clear();
    await local.set({ deviceId, kdfPins });
    ws?.close();
    return {};
  },
};

chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  // Extension pages (popup, unlock window) vs. content scripts in web pages. Not sender.tab: the unlock window is a tab too.
  const fromPage = !sender.url?.startsWith(chrome.runtime.getURL(''));
  const run = fromPage
    ? {
      suggest: () => suggest(sender), fill: () => fill(msg, sender), openUnlock,
      suggestTotp: () => suggestTotp(sender), totp: () => totpCode(msg, sender),
      captured: () => captured(msg, sender), stepUser: () => stepUser(msg, sender),
      pendingOffer: () => pendingOffer(sender), offerAction: () => offerAction(msg, sender),
    }[msg.type]
    : popupOnly[msg.type] && (() => popupOnly[msg.type](msg));
  if (!run) return;
  Promise.resolve(run()).then((r) => reply(r ?? {}), (e) => reply({ error: e.message }));
  return true;
});

chrome.commands.onCommand.addListener(async (cmd, tab) => {
  if (!(await session.get('index')).index) return openUnlock();
  const res = await chrome.tabs.sendMessage(tab.id, { type: 'hotkey' }).catch(() => null); // rejects if no frame answers
  if (!res?.handled) chrome.action.openPopup().catch((e) => console.warn('openPopup', e));
});

chrome.windows.onRemoved.addListener(async (id) => {
  if ((await session.get('unlockWin')).unlockWin === id) session.remove('unlockWin');
});

chrome.idle.setDetectionInterval(IDLE_LOCK_SECONDS);
chrome.idle.onStateChanged.addListener((state) => { if (state !== 'active') lock(); });

const injectContent = (tabId) => chrome.scripting.executeScript({ target: { tabId, allFrames: true }, files: ['content.js'] });

chrome.runtime.onInstalled.addListener(async () => {
  chrome.alarms.create('sync', { periodInMinutes: 30 });
  // Chrome only injects manifest content scripts on new page loads; cover tabs that are already open.
  for (const t of await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] })) injectContent(t.id).catch(() => {});
});
chrome.alarms.onAlarm.addListener(async () => {
  connectHub(); // reconnect if the worker was restarted
  if ((await local.get('refreshToken')).refreshToken) sync().catch((e) => console.warn('sync', e));
});
connectHub();
