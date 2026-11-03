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
| 16 | Granting access to other users | Done | Owners grant read or edit by email. Stored in the `grants` table. Every grant and revoke is audited |
| 17 | Access still works after being revoked | Done | `authorize()` checks the database on every request, so old links stop working at once. Tested by hand: viewer's saved download link gave 404 after revoke |
| 18 | A person with read access shares or deletes the document | Done | Share and delete are owner-only in `authorize()`. A grant can never allow them |
| 19 | Owner learns which emails have accounts by trying to share | Accepted | The share form says "Could not share" for any bad email, but a successful share confirms the account exists. Low risk: only document owners can use it |
| 20 | A person with only read access changes a document | Done | The edit route calls `authorize(..., "edit")`. A read grant is refused with 404 and an audit row. Tested by hand |
| 21 | An edit swaps a document for a different file type | Done | The new file must have the same extension as the original and pass the content check |
| 22 | Search shows documents the person was not given | Done | Search filters a list already built from `authorize()`, so it can never add documents. Tested with a second owner |
| 23 | No version history: an edit replaces the old file | Accepted | The old file is deleted. The audit log records the old and new fingerprints. Versions are not built |
| 24 | Tests still pass after a permission check is removed | Done | Removed the `authorize()` call from `load_or_404`: 14 tests failed. Removed the owner check in `authorize()`: 8 tests failed. Removed the revoked-grant filter: 1 test failed (`test_revoke_takes_effect_immediately`). Each break was undone with git |
| 25 | Revocation is covered by only one test | Accepted | One test proves a revoked person loses access at once. A second, separate test would be stronger. Planned if time allows |
| 26 | Uploaded files lost or exposed on the hosting disk | Done | Files are stored as rows in the database (`file_blobs`), not as files on disk. Nothing is served from a folder. Only code that passes `authorize()` reads them |
| 27 | Secret key left at the development default when live | Done | The app refuses to start in production without `SECRET_KEY` |
| 28 | Audit log shows the proxy's address instead of the user's | Done | `ProxyFix` reads the real client address, in production only |
| 29 | Deleted documents stay in the database | Accepted | Delete is a soft delete so documents can be recovered. A permanent purge is not built |
| 30 | File contents are stored unencrypted in the database | Accepted | The database is private and reached only through the app. Encryption at rest is not built |