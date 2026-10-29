// Inline suggestions under login / 2FA / new-password fields, and the save/update prompt after a login.
(() => {
  const TEXTISH = 'input[type=text], input[type=email], input[type=tel], input:not([type])';
  const visible = (el) => el.getClientRects().length > 0 && !el.disabled && !el.readOnly;
  const scopeOf = (el) => el.form || document;
  const passwordIn = (scope) => [...scope.querySelectorAll('input[type=password]')].find(visible);
  const before = (a, b) => a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING;

  function usernameFor(pw, scope) {
    return [...scope.querySelectorAll(TEXTISH)].filter((el) => visible(el) && before(el, pw)).pop();
  }

  function isLoginField(el) {
    if (!(el instanceof HTMLInputElement) || !visible(el)) return false;
    if (el.type === 'password') return true;
    if (!el.matches(TEXTISH)) return false;
    const pw = passwordIn(scopeOf(el));
    if (pw) return usernameFor(pw, scopeOf(el)) === el;
    // two-step logins (username first, password on the next page)
    return /username|email/.test(el.autocomplete) || /user|login|mail|account/i.test(el.name + ' ' + el.id);
  }

  // 2FA code field. shortcut: one input per code; split-digit inputs (6 boxes) are not handled
  const isOtpField = (el) => el instanceof HTMLInputElement && visible(el) && ['text', 'tel', 'number'].includes(el.type)
    && (el.autocomplete === 'one-time-code' || /one.?time|otp|totp|2fa|mfa|two.?factor|verification.?code|auth\w*.?code|security.?code|sicherheitscode|bestätigungscode/i
      .test([el.name, el.id, el.placeholder, el.getAttribute('aria-label')].join(' ')));
  const OLD_PW = /current|old|alt|aktuell|bisher/i;
  // password field for a new password (sign-up / change form)
  const isNewPassword = (el) => el.type === 'password' && !OLD_PW.test(`${el.name} ${el.id} ${el.autocomplete}`) && (el.autocomplete === 'new-password'
    || /new|neu|confirm|repeat|wiederhol|bestätig|regist|signup/i.test(`${el.name} ${el.id} ${el.placeholder}`)
    || scopeOf(el).querySelectorAll('input[type=password]').length >= 2);
  const isField = (el) => isOtpField(el) || isLoginField(el);

  function generatePassword(len = 20) {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-=?@_';
    const out = [];
    while (out.length < len) {
      for (const b of crypto.getRandomValues(new Uint8Array(len * 2))) {
        if (b < 256 - (256 % chars.length) && out.length < len) out.push(chars[b % chars.length]); // rejection sampling: uniform
      }
    }
    return out.join('');
  }

  function setValue(el, value) {
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  const host = document.createElement('div');
  host.style.cssText = 'all:initial;position:fixed;z-index:2147483647;display:none';
  const root = host.attachShadow({ mode: 'closed' });
  root.innerHTML = `<style>
    :host { --bg:#ffffffee; --fg:#15151c; --mute:#6e6e7d; --line:#e6e6ef; --sel:#efecff; --acc:#5b4ee8; }
    @media (prefers-color-scheme: dark) { :host { --bg:#1b1b22ee; --fg:#ececf2; --mute:#8d8d9c; --line:#2c2c36; --sel:#2a2645; --acc:#8b7dff; } }
    .box { margin-top:6px; width:300px; max-width:calc(100vw - 16px); background:var(--bg); color:var(--fg);
           -webkit-backdrop-filter:blur(16px) saturate(1.6); backdrop-filter:blur(16px) saturate(1.6);
           border:1px solid var(--line); border-radius:14px; overflow:hidden;
           box-shadow:0 2px 6px #0000001a, 0 18px 40px #0000002e;
           font:13px/1.35 -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif; -webkit-font-smoothing:antialiased;
           animation:pop .14s cubic-bezier(.2,.9,.3,1.2); transform-origin:top left; }
    @keyframes pop { from { opacity:0; transform:translateY(-4px) scale(.98); } }
    .head { display:flex; align-items:center; gap:7px; padding:8px 12px 6px; color:var(--mute); font-size:11px; font-weight:600; letter-spacing:.04em; text-transform:uppercase; }
    .logo { width:16px; height:16px; border-radius:5px; background:linear-gradient(135deg,#3b82f6,#6d28d9); display:grid; place-items:center; }
    .logo svg { width:10px; height:10px; fill:#fff; }
    .head span { flex:1; }
    kbd { font:inherit; font-size:10px; text-transform:none; letter-spacing:0; padding:1px 5px; border-radius:4px; border:1px solid var(--line); }
    ul { margin:0; padding:0 6px 6px; list-style:none; max-height:280px; overflow:auto; }
    li { display:flex; align-items:center; gap:10px; padding:7px 8px; border-radius:10px; cursor:pointer; }
    li[aria-selected=true] { background:var(--sel); }
    .av { width:30px; height:30px; border-radius:9px; flex:none; display:grid; place-items:center; color:#fff; font-weight:700; font-size:13px; }
    .av svg { width:15px; height:15px; fill:none; stroke:#fff; stroke-width:2.2; stroke-linecap:round; stroke-linejoin:round; }
    .txt { min-width:0; flex:1; }
    .name, .user { overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .name { font-weight:600; }
    .user { color:var(--mute); font-size:12px; }
    .enter { color:var(--acc); font-size:15px; opacity:0; }
    li[aria-selected=true] .enter { opacity:1; }
  </style><div class="box"><div class="head"><div class="logo"><svg viewBox="0 0 128 128"><circle cx="64" cy="41" r="22"/><path d="M71 49 L48 83 H62 L54 111 L84 69 H69 L78 49 Z"/></svg></div><span>Vaultfill</span><kbd>↑↓</kbd><kbd>⏎</kbd></div><ul role="listbox" aria-label="Zugangsdaten"></ul></div>`;
  const list = root.querySelector('ul');
  const LOCK = '<svg viewBox="0 0 24 24"><rect x="4" y="11" width="16" height="10" rx="2.5"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>';
  const KEY = '<svg viewBox="0 0 24 24"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 9.3-9.3M17 6l3 3M14 9l2 2"/></svg>';
  const GEN = { gen: true, name: 'Starkes Passwort generieren', username: 'Füllt Passwort und Wiederholung' };
  const LOCKED = { locked: true, name: 'Vault gesperrt', username: 'Klicken zum Entsperren' };

  let target = null, field = null, all = [], items = [], sel = 0; // all = suggestions for `field`, items = filtered view

  function hide() { host.style.display = 'none'; target = null; }

  // Stable colour per entry name.
  const hue = (s) => [...s].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 360, 7);

  function render() {
    list.replaceChildren(...items.map((it, i) => {
      const li = document.createElement('li');
      li.setAttribute('role', 'option');
      li.setAttribute('aria-selected', i === sel);
      const av = document.createElement('div');
      av.className = 'av';
      const h = hue(it.name || '?');
      av.style.background = it.locked || it.gen ? 'linear-gradient(135deg,#3b82f6,#6d28d9)' : `linear-gradient(135deg, hsl(${h} 70% 58%), hsl(${(h + 40) % 360} 65% 48%))`;
      if (it.locked || it.gen) av.innerHTML = it.gen ? KEY : LOCK; else av.textContent = (it.name.trim()[0] || '?').toUpperCase();
      const txt = document.createElement('div');
      txt.className = 'txt';
      const name = document.createElement('div'), user = document.createElement('div');
      name.className = 'name'; name.textContent = it.name;
      user.className = 'user'; user.textContent = it.username || '—';
      txt.append(name, user);
      const enter = document.createElement('span');
      enter.className = 'enter'; enter.textContent = '↵';
      li.append(av, txt, enter);
      li.addEventListener('mousedown', (e) => { e.preventDefault(); if (e.isTrusted) choose(i); });
      li.addEventListener('mousemove', () => { if (sel !== i) { sel = i; render(); } });
      return li;
    }));
  }

  async function show(el) {
    let res;
    const otp = isOtpField(el);
    try { res = await chrome.runtime.sendMessage({ type: otp ? 'suggestTotp' : 'suggest' }); } catch { return; } // extension reloaded
    if (document.activeElement !== el) return;
    const found = otp ? (res.items || []).map((it) => ({ ...it, totp: true, username: `${it.code.replace(/(\d{3})(?=\d)/g, '$1 ')} · ${it.username || 'Code'}` })) : res.items || [];
    all = [...(isNewPassword(el) ? [GEN] : []), ...(res.locked ? [LOCKED] : found)];
    field = el;
    filter(); // unfiltered on open: a page could pre-set the value to probe entry names
  }

  // Narrow suggestions to what the user typed (never by a password field's value).
  function filter(typed = '') {
    const q = field.type === 'password' ? '' : typed.trim().toLowerCase();
    items = all.filter((it) => it.locked || it.gen || it.totp || !q || it.name.toLowerCase().includes(q) || it.username?.toLowerCase().includes(q));
    if (!items.length) return hide();
    target = field; sel = 0;
    render();
    const r = field.getBoundingClientRect();
    host.style.left = `${Math.max(8, Math.min(r.left, innerWidth - 308))}px`;
    host.style.top = `${r.bottom}px`;
    host.style.display = 'block';
    if (!host.isConnected) document.documentElement.append(host);
  }

  function fillFields(el, cred) {
    const scope = scopeOf(el);
    const pw = el.type === 'password' ? el : passwordIn(scope);
    const user = pw ? usernameFor(pw, scope) : el;
    if (user && cred.username) setValue(user, cred.username);
    if (pw && cred.password) setValue(pw, cred.password);
  }

  async function choose(i) {
    const it = items[i], el = target;
    hide();
    if (it.locked) return chrome.runtime.sendMessage({ type: 'openUnlock' });
    if (it.gen) return fillNewPassword(el);
    if (it.totp) {
      const r = await chrome.runtime.sendMessage({ type: 'totp', id: it.id }); // fresh code, the listed one may have expired
      if (!r.error) setValue(el, r.code);
      return;
    }
    const cred = await chrome.runtime.sendMessage({ type: 'fill', id: it.id });
    if (!cred.error) fillFields(el, cred);
  }

  // Same generated password into every "new password" field of the form (password + confirmation).
  function fillNewPassword(el) {
    const pw = generatePassword();
    for (const f of scopeOf(el).querySelectorAll('input[type=password]')) if (visible(f) && isNewPassword(f)) setValue(f, pw);
    if (!isNewPassword(el)) setValue(el, pw);
  }

  // Focused login field, else the first one on the page.
  const loginField = () => isField(document.activeElement) ? document.activeElement
    : [...document.querySelectorAll('input')].find(isField);

  // Hotkey goes to every frame: only the frame with the focused login field (or the top frame, if no frame
  // has one focused) answers. No answer / handled:false → background opens the popup instead.
  chrome.runtime.onMessage.addListener((msg, _, reply) => {
    if (msg.type === 'showOffer') { showOffer(msg.offer); return reply({}); }
    const el = loginField();
    if (msg.type === 'fillCred') {
      if (el && msg.origin === location.origin) fillFields(el, msg); // page may have navigated since the popup opened
      return reply({});
    }
    if (msg.type !== 'hotkey' || !el || (document.activeElement !== el && (window !== top || document.activeElement?.tagName === 'IFRAME'))) return;
    hotkey(el).then((handled) => reply({ handled }), () => reply({ handled: false }));
    return true;
  });

  async function hotkey(el) {
    const otp = isOtpField(el);
    const res = await chrome.runtime.sendMessage({ type: otp ? 'suggestTotp' : 'suggest' });
    if (otp && res.items?.length === 1) { setValue(el, res.items[0].code); return true; }
    if (res.items?.length === 1) {
      const cred = await chrome.runtime.sendMessage({ type: 'fill', id: res.items[0].id });
      if (!cred.error) fillFields(el, cred);
      return !cred.error;
    }
    if (!res.items?.length) return false;
    el.focus();
    show(el);
    return true;
  }

  document.addEventListener('focusin', (e) => { if (isField(e.target)) show(e.target); else hide(); }, true);
  document.addEventListener('click', (e) => { if (!target && e.target === document.activeElement && isField(e.target)) show(e.target); }, true);
  // isTrusted: our own fill dispatches input events too, those must not re-open the list
  // typing an own password: get out of the way (the list would cover the submit button)
  document.addEventListener('input', (e) => {
    if (!e.isTrusted || e.target !== field || document.activeElement !== field) return;
    if (field.type === 'password') hide(); else filter(field.value);
  }, true);
  document.addEventListener('focusout', (e) => { if (e.target === target) hide(); }, true);
  document.addEventListener('scroll', hide, true);
  window.addEventListener('resize', hide);
  // isTrusted: a page must not drive the list with synthetic key events (Enter would fill and hand it the password)
  document.addEventListener('keydown', (e) => {
    if (!e.isTrusted || host.style.display === 'none' || e.target !== target) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') sel = (sel + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length, render();
    else if (e.key === 'Enter') choose(sel);
    else if (e.key === 'Escape') hide();
    // ⌘C username / ⌘⇧C password of the selected entry — unless the user selected text in the field
    else if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'c' && target.selectionStart === target.selectionEnd && !items[sel].locked) copy(sel, e.shiftKey);
    else return;
    e.preventDefault();
    e.stopPropagation();
  }, true);

  async function copy(i, password) {
    const it = items[i];
    if (it.gen) return;
    const cred = await chrome.runtime.sendMessage({ type: it.totp ? 'totp' : 'fill', id: it.id });
    if (cred.error) return;
    await navigator.clipboard.writeText(it.totp ? cred.code : password ? cred.password : cred.username);
    const user = list.children[i]?.querySelector('.user');
    if (user) user.textContent = `✓ ${it.totp ? '2FA-Code' : password ? 'Passwort' : 'Benutzername'} kopiert`;
    setTimeout(() => target && render(), 1200);
  }

  // --- save / update offer after a login form was submitted -------------------------------

  let lastCapture = '';
  function capture(scope) {
    if (host.style.display !== 'none') return; // Enter/click belongs to our dropdown
    // only real user submits: a script could otherwise submit chosen passwords (to overwrite entries or probe them)
    if (navigator.userActivation && !navigator.userActivation.isActive) return;
    scope ||= document;
    const pws = [...scope.querySelectorAll('input[type=password]')].filter((p) => p.value);
    if (!pws.length) { // first step of a two-step login: remember the username for the password page
      const user = [...scope.querySelectorAll(TEXTISH)].find((el) => el.value && isLoginField(el));
      if (user) chrome.runtime.sendMessage({ type: 'stepUser', username: user.value }).catch(() => {});
      return;
    }
    const pw = pws.find(isNewPassword) || pws[pws.length >= 3 ? 1 : 0]; // change forms: current, new, confirm
    const username = usernameFor(pws[0], scope)?.value || '';
    if (`${username}\0${pw.value}` === lastCapture) return; // submit + click fire for the same login
    lastCapture = `${username}\0${pw.value}`;
    chrome.runtime.sendMessage({ type: 'captured', username, password: pw.value }).then((r) => r?.offer && showOffer(r.offer)).catch(() => {});
  }

  const SUBMITISH = /log.?in|sign.?in|anmeld|einlog|weiter|next|continue|regist|sign.?up|konto erstellen|create|speichern|save|ändern|change|submit|senden/i;
  document.addEventListener('submit', (e) => capture(e.target), true);
  document.addEventListener('click', (e) => {
    const b = e.isTrusted && e.target.closest?.('button, input[type=submit], input[type=button], [role=button]');
    if (b && (b.type === 'submit' || SUBMITISH.test(`${b.textContent} ${b.value || ''} ${b.getAttribute('aria-label') || ''}`))) capture(b.closest('form'));
  }, true);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && e.isTrusted && !e.defaultPrevented && e.target instanceof HTMLInputElement && (e.target.type === 'password' || isLoginField(e.target))) capture(e.target.form);
  }, true);

  const card = document.createElement('div');
  card.style.cssText = 'all:initial;position:fixed;z-index:2147483647;top:16px;right:16px';
  const cardRoot = card.attachShadow({ mode: 'closed' });

  function showOffer(o) {
    if (window !== top) return; // iframes: background relays the offer to the top frame
    cardRoot.innerHTML = `<style>
      :host { --bg:#fffffff2; --fg:#15151c; --mute:#6e6e7d; --line:#e6e6ef; --field:#0000000d; --acc:#5b4ee8; }
      @media (prefers-color-scheme: dark) { :host { --bg:#1d1d24f2; --fg:#ececf2; --mute:#9393a3; --line:#ffffff1a; --field:#ffffff12; --acc:#8b7dff; } }
      .card { width:320px; background:var(--bg); color:var(--fg); border:1px solid var(--line); border-radius:14px; padding:14px;
              -webkit-backdrop-filter:blur(16px); backdrop-filter:blur(16px); box-shadow:0 2px 6px #0000001a, 0 18px 40px #0000002e;
              font:13px/1.4 -apple-system, BlinkMacSystemFont, "Inter", "Segoe UI", sans-serif; display:flex; flex-direction:column; gap:10px;
              animation:in .18s cubic-bezier(.2,.9,.3,1.2); }
      @keyframes in { from { opacity:0; transform:translateY(-6px); } }
      .head { display:flex; align-items:center; gap:10px; }
      .logo { width:28px; height:28px; border-radius:8px; background:linear-gradient(135deg,#3b82f6,#6d28d9); display:grid; place-items:center; flex:none; }
      .logo svg { width:16px; height:16px; fill:#fff; }
      .t { flex:1; min-width:0; } .t b { display:block; } .t span { color:var(--mute); font-size:12px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; display:block; }
      .x { border:0; background:none; color:var(--mute); font-size:18px; cursor:pointer; padding:0 4px; }
      label { display:flex; flex-direction:column; gap:4px; font-size:11.5px; font-weight:600; color:var(--mute); }
      input { font:inherit; font-weight:400; color:var(--fg); background:var(--field); border:1px solid transparent; border-radius:9px; padding:7px 10px; outline:none; }
      input:focus { border-color:var(--acc); }
      .row { display:flex; gap:8px; }
      button.b { flex:1; font:inherit; font-weight:600; border:0; border-radius:9px; padding:8px 10px; cursor:pointer; transition:opacity .2s; }
      button.b:disabled { opacity:.5; cursor:default; }
      .primary { background:linear-gradient(135deg,#3b82f6,#6d28d9); color:#fff; }
      .ghost { background:var(--field); color:var(--fg); }
      .err { color:#e5484d; font-size:12px; margin:0; } .err:empty { display:none; }
    </style>
    <div class="card" role="dialog" aria-label="Vaultfill">
      <div class="head"><div class="logo"><svg viewBox="0 0 128 128"><circle cx="64" cy="41" r="22"/><path d="M71 49 L48 83 H62 L54 111 L84 69 H69 L78 49 Z"/></svg></div>
        <div class="t"><b></b><span></span></div><button class="x" aria-label="Schließen">×</button></div>
      <label class="nameL">Name<input name="name"></label>
      <label class="userL">Benutzername<input name="username"></label>
      <p class="err"></p>
      <div class="row"><button class="b ghost never">Nie für diese Seite</button><button class="b primary save"></button></div>
    </div>`;
    const $ = (s) => cardRoot.querySelector(s);
    const update = o.kind === 'update';
    $('b').textContent = update ? 'Passwort aktualisieren?' : 'Login speichern?';
    $('.t span').textContent = update ? `${o.name} · ${o.username} · ${o.host}` : o.host;
    $('.save').textContent = update ? 'Aktualisieren' : 'Speichern';
    $('[name=name]').value = o.name;
    $('[name=username]').value = o.username || '';
    $('.nameL').hidden = $('.userL').hidden = update;
    const act = async (action) => {
      const res = await chrome.runtime.sendMessage({ type: 'offerAction', action, name: $('[name=name]').value, username: $('[name=username]').value }).catch((e) => ({ error: e.message }));
      if (res?.error) { $('.err').textContent = res.error; return; }
      if (action !== 'save') return card.remove();
      cardRoot.querySelector('.card').replaceChildren(Object.assign(document.createElement('b'), { textContent: update ? '✓ Passwort aktualisiert' : '✓ Login gespeichert' }));
      setTimeout(() => card.remove(), 1400);
    };
    // buttons arm after a moment so a click aimed at the page underneath cannot land on them
    for (const b of cardRoot.querySelectorAll('button.b')) { b.disabled = true; setTimeout(() => (b.disabled = false), 600); }
    $('.save').onclick = (e) => e.isTrusted && act('save');
    $('.never').onclick = (e) => e.isTrusted && act('never');
    $('.x').onclick = () => act('dismiss');
    cardRoot.addEventListener('keydown', (e) => { if (e.key === 'Escape') act('dismiss'); if (e.key === 'Enter') act('save'); });
    document.documentElement.append(card);
  }

  if (window === top) chrome.runtime.sendMessage({ type: 'pendingOffer' }).then((r) => r?.offer && showOffer(r.offer)).catch(() => {});

  // Field already focused when the script loads (autofocus on login pages).
  if (isField(document.activeElement)) show(document.activeElement);
})();
