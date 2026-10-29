# Vaultfill

Schlanke Chrome-Extension für Vaultwarden: Fokus auf ein Login-Feld → Dropdown mit passenden Zugangsdaten → Klick oder Enter füllt Benutzername + Passwort.

## Installieren

1. `chrome://extensions` → Entwicklermodus an → **Entpackte Erweiterung laden** → diesen Ordner wählen.
2. Extension-Icon → Server-URL, E-Mail, Master-Passwort → Anmelden (2FA: TOTP oder E-Mail).
3. Nach Browser-Neustart: Icon → Master-Passwort → Entsperren (oder im Dropdown auf „Vault gesperrt“ klicken).

## Bedienung

- **Login-Feld fokussieren** → Vorschläge (zuletzt benutzte zuerst), ↑/↓, Enter, Esc.
- **⌘⇧L** (Windows/Linux: Strg+Shift+L) → genau ein Treffer: sofort füllen, sonst Vorschläge. Ändern unter `chrome://extensions/shortcuts`.
- **Popup** → Suche über alle Einträge; Klick füllt die aktuelle Seite. Optional „URL dieser Seite beim Eintrag speichern“.
- **Sperren**: automatisch nach 30 min Leerlauf oder bei Bildschirmsperre. Entsperren per Touch ID, PIN (bis Browser-Neustart) oder Master-Passwort. Einrichten im Popup unter „Entsperren ohne Master-Passwort“.
- **Neue/geänderte Logins**: nach dem Absenden fragt eine Karte oben rechts „Login speichern?“ bzw. „Passwort aktualisieren?“ (altes Passwort landet in der Historie). „Nie für diese Seite“ merkt sich die Domain.
- **Registrierung**: in Feldern für ein neues Passwort schlägt das Dropdown „Starkes Passwort generieren“ vor (füllt Passwort + Wiederholung).
- **2FA**: im Code-Feld zeigt das Dropdown den aktuellen TOTP-Code passender Einträge; ⌘⇧L füllt ihn direkt.
- **Sync**: live über Vaultwardens Notification-Hub, zusätzlich alle 30 min.

## Wie es funktioniert

- `vault.js` – Bitwarden-Protokoll: Prelogin, KDF (PBKDF2 / Argon2id via hash-wasm), Token, Sync, AES-CBC+HMAC-Entschlüsselung, URI-Matching.
- `background.js` – verschlüsselter Vault + Tokens in `storage.local`; User-Key und entschlüsselter Index (ohne Passwörter) nur in `storage.session` (RAM). Passwörter werden erst beim Füllen entschlüsselt, und nur für Einträge, die zur URL des anfragenden Frames passen. Sync alle 30 min.
- Touch ID: WebAuthn-Passkey mit PRF-Erweiterung; das PRF-Ergebnis verschlüsselt eine Kopie des User-Keys. PIN: PIN-verschlüsselte Kopie nur in `storage.session`, 5 Fehlversuche → gelöscht.
- `content.js` – erkennt Login-Felder, zeigt das Dropdown (geschlossenes Shadow DOM), füllt Felder.

## Tests

`npm test` – URI-Matching. E2E gegen echtes Vaultwarden + offizielle `bw` CLI: Anleitung oben in `test/vault.test.mjs`.
