# CLAUDE.md – Vaultfill for Chrome

Unofficial Vaultwarden/Bitwarden autofill extension (Chrome, Manifest V3, no build step): inline suggestions,
save/update after login, generator, TOTP, SSO, PIN/Touch ID. Sibling repo: `vaultfill-desktop`.
This repository is **public**. Treat every commit, issue and log as world-readable.

## Commands

```bash
npm test          # unit tests (must pass before every commit)
```

- Load for manual testing: `chrome://extensions` → developer mode → "Load unpacked" → this folder. No bundler, no transpiler – the folder *is* the extension.
- E2E against a throwaway Vaultwarden in Docker, cross-checked with the official `bw` CLI: see the header of `test/vault.test.mjs`.
- Content-script behaviour (dropdown, capture, generator, TOTP) is tested in headless Chrome via the DevTools protocol with a stubbed `chrome.runtime` – keep such checks for security-relevant changes.

## Layout

| Path | Role |
|---|---|
| `vault.js` | Protocol + crypto core. **Byte-identical copy in `vaultfill-desktop`** |
| `lib/psl.js` | Generated Public Suffix List – do not edit by hand |
| `background.js` | Service worker: state, SSO, unlock, save offers, live sync, idle lock |
| `content.js` | Runs in every page/frame: field detection, dropdown (closed shadow DOM), capture, save card |
| `popup.html/js` | Login, unlock, search, settings |

## Security invariants – never weaken without an explicit maintainer decision

- **Web pages are hostile.** In `content.js` everything that fills, copies, unlocks or captures must be driven by *trusted* user input (`event.isTrusted`, `navigator.userActivation`). Never act on synthetic events or page-set values.
- **Credentials only for the requesting frame's own site**: `fill`/`totp`/`suggest` check `sender.url` (set by Chrome), never data from the page. Matching via the Public Suffix List; https entries never on http pages; port = site; "starts with" only within the same origin.
- **Message authorization**: extension pages vs. content scripts are told apart by `sender.url` prefix (not `sender.tab`). Content scripts get only the narrow handler set.
- **Storage**: decrypted key and index only in `storage.session`; `storage.local` holds encrypted data and tokens only. Lock must clear key, index, parked offers (`offer:*`) and two-step usernames (`step:*`).
- **Save/update offers** stay bound to the registrable domain that produced them; never guess the entry to update.
- **DOM**: no `innerHTML` with vault or page data – `textContent`/`.value` only. UI lives in closed shadow roots.
- **Server is untrusted for parameters**: keep `checkKdf` (bounds + per-account pin) and https-only except local hosts.
- **Manifest**: no `web_accessible_resources`, no `externally_connectable`, CSP `script-src 'self' 'wasm-unsafe-eval'`. New permissions need a reason in the commit message.

Any change touching these needs a test that would fail if the guarantee broke.

## Conventions

- **`vault.js` is shared**: change it in both repos in the same way and keep the files identical (`cmp`). Same for its unit tests.
- **No build step, no runtime dependencies** besides the vendored `lib/`. Dev tooling only if it pays for itself.
- **Crypto**: WebCrypto only. No hand-rolled primitives beyond the Bitwarden formats already in `vault.js`.
- **Code** and comments in English; **UI text** in German. Comments explain *why*, not what.
- **Commits**: Conventional Commits in English (`feat:`, `fix(security):`, `docs:`, `test:`), one logical change per commit, body explains the reason.
- **Git**: never rewrite `main` or tags; no force pushes. Feature work on branches, merge via PR.

## Public-repo hygiene

- **Never commit**: keys, tokens, `.env`, exported vaults, Vaultwarden URLs/accounts of real people, personal paths (`/Users/<name>/…`), real e-mail addresses.
- **Test and screenshot data** is fictional only (`alice@example.com`, `Acme`, `example.com`); screenshots come from test pages with stubbed data – never from a real vault.
- **Security findings**: do not open public issues with exploit details; report privately to the maintainer.
- Before pushing, this must print nothing:
  `git grep -nIi -E "BEGIN (RSA |EC )?PRIVATE KEY|password=|/Users/" -- . ':!lib' ':!CLAUDE.md'`
