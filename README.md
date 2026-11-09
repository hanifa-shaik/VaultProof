# VaultProof

Secure document sharing where only people who were granted a document can reach it, and every attempt, including refused ones, is recorded in a tamper-evident audit log.

**Live site:** https://trustvault-hanifa.onrender.com (the free host sleeps, so the first load takes about a minute)

**Demo video:** https://drive.google.com/file/d/1VvGy7tgyg_hlCB37xEwYe5GwLGGjj_zK/view

The free host goes to sleep when idle, so the first page load can take about a minute. Please wait for it.

**Repository:** https://github.com/hanifa-shaik/VaultProof


## Demo accounts
| Role | Email | Password |
|---|---|---|
| Admin | admin@trustvault.test | TrustVault12345 |
| Owner | owner@trustvault.test | TrustVault12345 |
| Viewer | viewer@trustvault.test | TrustVault12345 |

The demo owner has two documents: `welcome.txt` (shared with the demo viewer as read) and `private-notes.txt` (shared with nobody).

## What each role can do
- **Owner:** upload documents, edit and delete their own, share read or edit access by email, take it back.
- **Viewer:** open only documents shared with them. Cannot upload.
- **Admin:** see users, document names and details, the audit log and alerts, and disable accounts. Cannot read any file contents.

Registration only offers Owner and Viewer. An admin account can only be created by the seed script on the server.

## My permission model
Every document has exactly one owner, the owner-role user who uploaded it, and nobody else can reach it unless that owner gives them access. Access is a grant: one row for one person and one document, at level read or edit, which can be revoked or can expire. One function, `authorize(user, document, action)` in `permissions/__init__.py`, decides every question about a document, and its default answer is no. Every route that touches a document goes through it, so the decision is made on the server each time and is not just a hidden button. The owner may do everything. Anyone else needs an active grant: read allows downloading, edit allows downloading and replacing the file, and deleting and sharing are owner-only and can never be given through a grant. The grant is read from the database on every request and I issue no download links or tokens, so revoking access works on the very next request. Admins have no path in `authorize()`, so they can monitor activity but never open a file. When someone is refused, the answer is 404, the same as for a document that does not exist, and the attempt is written to the audit log.

## Audit trail
Uploads, downloads, edits, deletions, grants, revokes, logins, registrations, admin actions and refused attempts are all recorded. Each row stores the hash of the row before it, so changing an old row breaks the chain, and the admin page has a Verify audit integrity button. On PostgreSQL, database triggers also refuse any UPDATE, DELETE or TRUNCATE on the audit table, and the admin page shows the newest row's fingerprint so a copy can be kept outside the system.


## What I built
Registration and login with roles, upload with content checks, per-document read and edit grants, immediate revocation, search by name, owner, category and date, edit, soft delete, an audit log with a hash chain and database triggers, an admin dashboard with alerts and an integrity check, login rate limiting, security headers, and 56 automated tests.

## What I deliberately did not build
Sharing with outside people, versions, retention rules, encryption at rest, password reset, multi-factor login, and the AI suggestion feature. See THREATS.md for why.

## Unfinished or weak
- There is no screen to set a grant's expiry. The expiry check exists in `authorize()` and is tested, but owners cannot set one yet.
- There is no Content-Security-Policy header.
- The automated tests run on SQLite and production runs PostgreSQL, so the database triggers and the audit lock were checked by hand on the live database and are not covered by automated tests.
- Revocation is covered by one automated test, backed up by a manual test.
- Editing a document replaces the old file. There is no version history.
- Deleted documents are only marked deleted. There is no permanent purge.
- Login rate limiting does not stop an attacker who uses many different addresses.

## How to run it
Python 3.12 or newer is recommended. SQLite is used locally, so there is no database to set up.

    git clone https://github.com/hanifa-shaik/VaultProof.git
    git clone <https://github.com/hanifa-shaik/VaultProof.git>
    cd VaultProof
    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt
    python seed.py
    python app.py
Open http://127.0.0.1:5000 . Local demo password: TestPass12345.

## Tests
    python -m pytest -q

56 tests cover access control (another owner, a viewer, an anonymous visitor, read and edit grants, revocation, expiry, disabled users, deleted documents), the audit log (refused attempts recorded, tampering detected), uploads, registration and login, and the admin pages. Six of them attack revocation directly: access lost on the next request, revoking an edit grant, revoking one person leaves others alone, re-granting restores access, only the owner can revoke, and a revoke cannot be pointed at another document's grant.

## Deployment
Neon (PostgreSQL) and Render. Build command: `pip install -r requirements.txt && python seed.py`. Start command: `gunicorn app:app --timeout 60`. Environment variables: PYTHON_VERSION, APP_ENV=production, SECRET_KEY, DATABASE_URL, SEED_PASSWORD. The schema is in schema.sql.

## API documentation
See API.md for each endpoint and who is allowed to call it.

## How I used AI
I used ChatGPT to plan the project and Claude to guide me through building it step by step. I ran every step myself and tested it. PROMPTS.md lists the places where the AI was wrong and what I did about each one, with commit links.

## Other files
THREATS.md (the threats I found and what I did about each), PROMPTS.md, API.md, schema.sql
