# TrustVault - Security Threats

Only things that exist in the code are marked Done. Everything else says Planned or Accepted.

| # | Threat | Status | What I did |
|---|--------|--------|------------|
| 1 | Unauthorized document access | Planned | Roles exist, but document permissions are not built yet. Plan: one `authorize()` function that denies by default, called by every route |
| 2 | Password theft | Done | Passwords are hashed, never stored as plain text |
| 3 | Cross-site request forgery (CSRF) | Done | Flask-WTF CSRF token is required on every POST |
| 4 | Someone registers as admin by editing the form | Done | Server checks the role against an allow-list (owner, viewer only) |
| 5 | Open redirect through the login `next` parameter | Done | `is_safe_next` allows only paths on our own site |
| 6 | Attacker learns which emails have accounts | Partly done | Same login error for every failure. Timing may still differ (accepted, low risk) |
| 7 | Password guessing | Planned | Rate limiting not built yet |
| 8 | Logins and actions not recorded | Planned | `log_event` exists, but no route calls it yet |
| 9 | Someone edits the audit log to hide activity | Partly done | Rows are hash-chained and `verify_chain` detects edits. Not yet blocked: someone with full database access could rebuild the chain. Planned: a database rule against UPDATE and DELETE, plus a saved checkpoint |
| 10 | Malicious or disguised file upload | Done | Extension allow-list, real content check (file signature), size limit, empty-file check, random storage name, refused uploads logged. Tested by hand with .zip and an empty file (add the others once you have run them) |
| 11 | A user opens another user's document by pasting its link | Done (owner-only for now) | Every download calls `authorize()`. Anyone else gets 404 and a `denied` audit row. Tested by hand with two owners |
| 12 | Guessing document IDs | Done | IDs are random UUIDs. "Not yours" and "does not exist" give the same 404 |
| 13 | Stored file changed on disk | Done | SHA-256 fingerprint is checked on every download |
| 14 | Uploaded file runs as a page in the browser | Done | Served as an attachment with `nosniff`, never from a public folder |
| 15 | Someone other than the owner deletes a document | Done | `delete` calls `authorize()`. POST-only with a CSRF token |
| 16 | Granting access to other users | Planned | Not built yet. Only owners can reach their own documents today |