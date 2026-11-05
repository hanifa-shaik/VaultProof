# TrustVault - Threats

Done = built. Tested = an automated test fails if it breaks. Checked live = I checked it by hand on the deployed site. Accepted = I know and chose to leave it. Not built = left out on purpose.

| # | Threat | Status | What I did |
|---|--------|--------|------------|
| 1 | Reading another person's document by pasting its link | Done, tested | Every download calls `authorize()` through `load_or_404`. Others get 404 and a denied audit row |
| 2 | Guessing document IDs | Done, tested | Random UUIDs. "Not yours" and "does not exist" give an identical 404 |
| 3 | Editing, sharing, granting, revoking or deleting through another route | Done, tested | All these routes use `load_or_404`. One test per route |
| 4 | A read grant used to edit | Done, tested | `authorize()` allows edit only for the owner or an edit grant |
| 5 | An edit grant used to share or delete | Done, tested | Share and delete are owner-only |
| 6 | Access after revoke | Done, tested | No tokens or links to expire. The grant is read from the database on every request. Checked by hand with a saved link |
| 7 | Expired grants | Partly done, tested | Expiry is enforced in `authorize()`. There is no screen to set an expiry yet |
| 8 | Old login works after an account is disabled | Done, tested | The user loader treats a disabled account as logged out. My test passed, which showed the AI's claim of a gap was wrong |
| 9 | Search or dashboard shows documents not given | Done, tested | Lists are built from `authorize()` first, then filtered |
| 10 | Admin reads file contents | Done, tested | The admin role has no path in `authorize()`, and the admin pages never read file bytes |
| 11 | Non-admin opens admin pages | Done, tested, checked live | `admin_only` returns 404 and records the attempt |
| 12 | Becoming an admin at registration | Done, tested | Allow-list of roles. The attempt is logged |
| 13 | Passwords stolen from the database | Done | Hashed with Werkzeug, never stored as text |
| 14 | Password guessing | Done, tested, checked live | 5 failures per email and address, or 20 per address, in 15 minutes gives 429. Someone with many addresses is not stopped (accepted) |
| 15 | Learning which emails have accounts | Partly done | Same login message for all failures. Timing may differ. A successful share confirms an account exists to owners (accepted) |
| 16 | Forged form posts (CSRF) | Done | Flask-WTF token on every POST. It is switched off only in tests, so no automated test covers it |
| 17 | Open redirect through `next` | Done, tested | `is_safe_next` |
| 18 | Logout by plain link | Done, tested | Logout is POST only |
| 19 | Disallowed upload type | Done, tested | Extension allow-list |
| 20 | Disguised file (text renamed .pdf or .png) | Done, tested | File signature check |
| 21 | Empty or oversized upload | Done | Empty refused (tested). The 10 MB limit is set but not tested |
| 22 | Path tricks in file names | Done, tested | `secure_filename` and a random storage name |
| 23 | Uploaded file runs in the browser | Done | Sent as an attachment with `nosniff`, content type from my own list. Not tested |
| 24 | Files readable from disk or a public URL | Done | File bytes live in the database. No folder is served |
| 25 | Stored file altered | Done | SHA-256 checked on every download. Not tested |
| 26 | Audit log edited or deleted | Done, tested, checked live | Hash chain and a verify button (tested). PostgreSQL triggers refuse UPDATE, DELETE and TRUNCATE. I ran an UPDATE on the live database and got `audit_log is append-only` |
| 27 | Newest audit rows removed | Partly done | A chain alone cannot show this. The triggers block it, and the admin page shows a fingerprint I copied outside the system |
| 28 | Two requests fork the audit chain | Done | Advisory lock on PostgreSQL. Not testable on SQLite |
| 29 | Refused attempts not recorded | Done, tested, checked live | Denied rows for downloads, edits, deletes, grants, uploads, logins and admin access |
| 30 | Secrets in the repository | Done | Keys only in Render settings. The app refuses to start in production without `SECRET_KEY`. Incident: a command printed a dev key, I photographed it, and I replaced it before deploying |
| 31 | Cookie theft | Done | HttpOnly, SameSite Lax, Secure in production, HTTPS. Not tested |
| 32 | Clickjacking, sniffing, cached pages | Done, tested | `X-Frame-Options`, `nosniff`, `no-store`, HSTS in production |
| 33 | Script injection (XSS) | Done | Jinja escapes output. No Content-Security-Policy yet (accepted) |
| 34 | Wrong IP in the audit log behind the proxy | Done | `ProxyFix` in production |
| 35 | Tests still pass after a check is removed | Done | Removed the `authorize()` call: 14 failed. Removed the owner check: 8 failed. Removed the revoked-grant filter: 1 failed. Removed the admin gate: 2 failed. Each undone with git |
| 36 | Demo passwords are public in the README | Accepted | The brief requires them. They are throwaway and I will change them after judging |
| 37 | Revocation is covered by only one automated test | Accepted | The by-hand test backs it up |
| 38 | Deleted documents stay stored | Accepted | Soft delete so they can be recovered. No purge |
| 39 | File contents not encrypted at rest | Accepted | The database is private and reached only through the app |
| 40 | Someone with database owner rights could drop the triggers | Accepted | A separate database role would fix it. Not done |
| 41 | Free hosting sleeps and has storage limits | Accepted | First load takes about a minute. The README warns judges |
| 42 | Tests run on SQLite, production runs PostgreSQL | Accepted | Triggers and locks are PostgreSQL only and checked by hand |
| 43 | Outside sharing, versions, retention, AI suggestions, MFA, password reset | Not built | Left out so the permission model stays small and tested |