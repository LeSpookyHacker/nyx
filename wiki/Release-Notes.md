# Release Notes

Short, human-readable highlights of recent changes to Nyx. For the full commit history, see the [repository log](https://github.com/LeSpookyHacker/nyx/commits/main).

---

## Latest

- **Proper sign-in flow.** The dashboard now has a dedicated `/login` page and a `ProtectedRoute` guard — paste your `NYX_API_KEY` once, the backend mints an opaque session token (random, not the key itself) stored in an HTTP-only `SameSite=Strict` cookie, and the server resolves it against a new `user_sessions` table. Deleting the row revokes the session immediately. The raw key never lives in the cookie jar.
- **API Keys management UI.** Settings now has a panel to list, create, and revoke scoped API keys (`scanner`, `readonly`, `analyst`, `admin`). The plaintext key is shown once at creation with a copy-to-clipboard action and an explicit "store it now" warning.
- **Integration health on the Settings page.** The dashboard polls `/health/integrations` every 30s and shows green/red dots for Database, Anthropic, GitHub, JIRA, and the notification webhook — the same data `./nyx.sh check` prints, now visible without leaving the UI.
- **Hardened dev fallback.** The silent-admin fallback for local development now refuses to activate when the instance looks production-ish (`GITHUB_WEBHOOK_ENDPOINT` set, or `HTTPS_ONLY=true`) — you can't accidentally ship an internet-reachable Nyx that auto-grants admin because someone forgot to set `NYX_API_KEY`.
- **First-class auth tests.** A new pytest suite covers missing/invalid/expired auth, session cookie lifecycle, session-id hashing, raw-key-as-cookie regression, the dev-fallback hardening, and webhook HMAC verification. 40 tests, running cleanly.

---

## Previous highlights

- **Dashboard empty state, theme toggle, saved filter views.**
- **`raw_output` encryption at rest** for scanner payloads.
- **Doctor canary** health probe for integration monitoring.
- **Opaque session tokens** and dedicated sign-in page.
- **API key UI** and **integration health** surfacing in Settings.

For the older change history, browse the [git log](https://github.com/LeSpookyHacker/nyx/commits/main).
