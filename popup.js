import { b64, unb64 } from './vault.js';

const $ = (s) => document.querySelector(s);
const params = new URLSearchParams(location.search);
const isWin = params.has('win'); // standalone window: unlock / Touch ID (WebAuthn would close the action popup)
document.body.classList.toggle('win', isWin);
let tabId, st, showSettings = false, autoTouch = true; // Touch ID auto-starts only when the popup opens, not after locking

async function send(msg) {
  $('#err').textContent = '';
  $('#err').className = 'err';
  document.querySelectorAll('button').forEach((b) => (b.disabled = true));
  try {
    const res = await chrome.runtime.sendMessage(msg);
    if (res?.error) throw new Error(res.error);
    return res;
  } catch (e) {
    $('#err').textContent = e.message;
    return null;
  } finally {
    document.querySelectorAll('button').forEach((b) => (b.disabled = false));
  }
}

const info = (text) => { $('#err').textContent = text; $('#err').className = 'err info'; };
const done = () => window.close();
const el = (tag, { dataset, ...props } = {}, ...kids) => {
  const e = Object.assign(document.createElement(tag), props);
  Object.assign(e.dataset, dataset);
  e.append(...kids);
  return e;
};
const icon = (id) => { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); s.innerHTML = `<use href="#i-${id}"/>`; return s; };

async function render() {
  st = await send({ type: 'status' });
  if (!st) return;
  let view = st.pendingTotp !== undefined ? 'totp' : !st.loggedIn ? 'login' : st.unlocked ? 'open' : 'unlock';
  if (view === 'open' && showSettings) view = 'settings';
  for (const id of ['login', 'totp', 'unlock', 'open', 'settings']) $(`#${id}`).hidden = id !== view;
  $('#bar').hidden = !['open', 'settings'].includes(view);
  $('#gear').replaceChildren(icon(showSettings ? 'back' : 'gear'));
  $('#gear').title = $('#gear').ariaLabel = showSettings ? 'Back' : 'Settings';

  $('#totpHint').textContent = st.pendingTotp === 1 ? 'Enter the code from the e-mail' : 'Enter the code from your authenticator app';
  $('#who').textContent = st.email;
  $('#unlock').password.placeholder = st.pinArmed ? 'PIN or master password' : 'Master password';
  $('#touch').hidden = $('#or').hidden = !st.touchId;
  $('#touchPill').textContent = st.touchId ? 'On' : 'Off';
  $('#touchPill').classList.toggle('on', !!st.touchId);
  $('#touchEnroll').hidden = !!st.touchId;
  $('#touchRemove').hidden = !st.touchId;
  $('#pinPill').textContent = st.pin ? 'On' : 'Off';
  $('#pinPill').classList.toggle('on', st.pin);
  $('#pinRemove').hidden = !st.pin;
  $('#info').textContent = `${st.count} logins · synced ${new Date(st.lastSync).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
  if (st.loginError) $('#err').textContent = st.loginError;
  const key = (await chrome.commands.getAll()).find((c) => c.name === 'fill')?.shortcut;
  $('#shortcut').textContent = key ? `Shortcut ${key} – change it at chrome://extensions/shortcuts.` : 'No shortcut assigned – set one at chrome://extensions/shortcuts.';

  if (view === 'open') {
    if (isWin && params.get('do') !== 'enroll') return done();
    if (!isWin) search();
  }
  if (!(view === 'unlock' && st.touchId && autoTouch)) $(`#${view} input`)?.focus(); // don't pull focus from the Touch ID prompt
  if (view === 'unlock' && st.touchId && autoTouch) touchUnlock();
  autoTouch = false;
  if (isWin && view === 'open' && params.get('do') === 'enroll') touchEnroll();
}

// --- search & fill ---------------------------------------------------------------------

const favicon = (site) => el('img', { src: `/_favicon/?pageUrl=${encodeURIComponent(site)}&size=32`, alt: '', onerror: (e) => e.target.replaceWith(icon('globe')) });

async function search() {
  tabId ??= (await chrome.tabs.query({ active: true, currentWindow: true }))[0]?.id;
  if (tabId === undefined) return;
  const q = $('#q').value.trim();
  const res = await send({ type: 'search', q, tabId });
  if (!res) return;
  $('#listLabel').replaceChildren(...(q ? ['Search results'] : res.host ? ['For', el('b', { textContent: res.host })] : ['This page']));
  $('#results').replaceChildren(...res.items.map((it) => el('li', { tabIndex: 0, dataset: { id: it.id }, onclick: () => fillTab(it.id), onkeydown: (e) => e.key === 'Enter' && fillTab(it.id) },
    el('span', { className: 'ico' }, it.site ? favicon(it.site) : icon('globe')),
    el('span', { className: 'txt' }, el('div', { className: 'name', textContent: it.name }), el('div', { className: 'user', textContent: it.username || '—' })),
    el('span', { className: 'go' }, icon('arrow')))));
  if (!res.items.length) {
    $('#results').append(el('li', { className: 'empty' }, el('div', {}, icon(q ? 'search' : 'globe'),
      el('div', { textContent: q ? 'Nothing found' : 'No logins for this page' }),
      el('div', { textContent: q ? 'Try a different search' : 'Search above to fill an entry', style: 'font-size:12px' }))));
  }
  $('#rememberRow').hidden = !res.host || !res.items.some((it) => !it.matches);
  $('#rememberHost').textContent = res.host || '';
}

async function fillTab(id) {
  if (await send({ type: 'fillTab', id, tabId, remember: $('#remember').checked })) done();
}

$('#q').addEventListener('input', search);
$('#q').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); $('#results li[tabindex]')?.click(); }
  if (e.key === 'ArrowDown') { e.preventDefault(); $('#results li[tabindex]')?.focus(); }
});
$('#results').addEventListener('keydown', (e) => {
  const sib = e.key === 'ArrowDown' ? e.target.nextElementSibling : e.key === 'ArrowUp' ? e.target.previousElementSibling ?? $('#q') : null;
  if (sib) { e.preventDefault(); sib.focus(); }
});

// ⌘C username / ⌘⇧C password of the focused entry (else the first one) — normal copy if text is selected.
document.addEventListener('keydown', async (e) => {
  if (!(e.metaKey || e.ctrlKey) || e.key.toLowerCase() !== 'c' || $('#open').hidden) return;
  const a = document.activeElement;
  if (getSelection().toString() || (a.selectionStart ?? 0) !== (a.selectionEnd ?? 0)) return;
  const id = (a.closest('li[data-id]') ?? $('#results li[data-id]'))?.dataset.id;
  if (!id) return;
  e.preventDefault();
  const cred = await send({ type: 'credentials', id });
  if (!cred) return;
  await navigator.clipboard.writeText(e.shiftKey ? cred.password : cred.username);
  info(`${e.shiftKey ? 'Password' : 'Username'} copied`);
});

$('#syncBtn').addEventListener('click', async () => {
  $('#syncBtn').classList.add('spin');
  const ok = await send({ type: 'sync' });
  $('#syncBtn').classList.remove('spin');
  if (ok) render();
});

$('#gear').addEventListener('click', () => { showSettings = !showSettings; render(); });

// --- Touch ID (WebAuthn PRF) -------------------------------------------------------------

const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
const openWin = (what) => chrome.windows.create({ url: `popup.html?win&do=${what}`, type: 'popup', width: 460, height: 440 }).then(done);

async function prfSecret({ credId, salt }) {
  const a = await navigator.credentials.get({ publicKey: {
    challenge: rnd(32), userVerification: 'required',
    allowCredentials: [{ type: 'public-key', id: unb64(credId) }],
    extensions: { prf: { eval: { first: unb64(salt) } } },
  } });
  const r = a.getClientExtensionResults().prf?.results?.first;
  if (!r) throw new Error('Touch ID returned no PRF result (not supported by Chrome/authenticator)');
  return b64(new Uint8Array(r));
}

async function touchEnroll() {
  try {
    const cred = await navigator.credentials.create({ publicKey: {
      rp: { name: 'Vaultfill' }, user: { id: rnd(16), name: st.email, displayName: st.email },
      challenge: rnd(32), pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      authenticatorSelection: { authenticatorAttachment: 'platform', userVerification: 'required', residentKey: 'discouraged' },
      extensions: { prf: {} },
    } });
    if (!cred.getClientExtensionResults().prf?.enabled) throw new Error('Touch ID without PRF support – cannot be used');
    const p = { credId: b64(new Uint8Array(cred.rawId)), salt: b64(rnd(32)) };
    if (await send({ type: 'enrollTouchId', ...p, secret: await prfSecret(p) })) done();
  } catch (e) {
    $('#err').textContent = e.message;
  }
}

async function touchUnlock() {
  try {
    if (await send({ type: 'unlockTouchId', secret: await prfSecret(st.touchId) })) isWin ? done() : render();
  } catch (e) {
    $('#err').textContent = e.name === 'NotAllowedError' ? 'Touch ID cancelled' : e.message;
  }
}

$('#touch').addEventListener('click', touchUnlock);
$('#touchEnroll').addEventListener('click', () => isWin ? touchEnroll() : openWin('enroll'));

// --- forms -----------------------------------------------------------------------------

$('#pinSet').addEventListener('click', async () => {
  if (await send({ type: 'setPin', pin: $('#pin').value })) { $('#pin').value = ''; render(); }
});

$('#login').addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await send({ type: 'login', ...Object.fromEntries(new FormData(e.target)) });
  if (res?.sso) info('Finish signing in in the new tab …');
  else if (res) render();
});

$('#totp').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (await send({ type: 'login', totp: e.target.totp.value })) render();
});

$('#unlock').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (await send({ type: 'unlock', password: e.target.password.value })) isWin ? done() : render();
});

document.addEventListener('click', async (e) => {
  const act = e.target.closest('[data-act]')?.dataset.act;
  if (!act || !(await send({ type: act }))) return;
  if (act === 'logout') showSettings = false;
  render();
});

render();
