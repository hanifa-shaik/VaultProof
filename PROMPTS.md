# PROMPTS.md

How I worked: I used ChatGPT to plan the project and Claude to guide me through building it, one small step at a time. I ran every step myself, tested it, and pasted back errors and screenshots. The entries below are real problems I hit, written as they happened.

## 2026-11-02: Templates folder in the wrong place

**What I asked:** For step-by-step help building registration and login for TrustVault in Flask.

**What it produced:** Code for auth/__init__.py and app.py, plus four HTML files, with instructions to put the HTML files in a folder called `templates`.

**What was wrong:** When I ran the app, Chrome showed `jinja2.exceptions.TemplateNotFound: login.html`. My `templates` folder had ended up inside the `auth` folder, but Flask looks for it next to app.py. The AI's first suggestion (check the folder and file names) did not solve it, and dragging the folder in VS Code did not work for me.

**What I did instead:** I used the terminal command `Move-Item auth\templates templates` to move the folder next to app.py. The login page then loaded.

**Commit:** https://github.com/hanifa-shaik/TrustVault/commit/750ee8633b6284958974e171600fb50b0b39d39b

**What I learned:** Flask finds templates by folder location, so where a file lives matters, not just what is inside it.

## 2026-11-02: The AI skipped the file-validation tests

**What I asked:** For step-by-step guidance on upload validation and private storage.

**What it produced:** Upload code with an extension allow-list, a file signature check and a size limit. It then moved on to the next part without any tests for the cases I most needed: a .zip, an .exe, a text file renamed to .pdf or .png, and an empty file.

**What was wrong:** I noticed the tests were missing and told it. Those cases are exactly what my threat list says the upload code must stop.

**What I did instead:** I made the test files and ran each case by hand against the running app. Refused uploads showed the right message and were recorded in the audit log. On 2026-11-03 I turned the same cases into automated tests.

**Commit:** https://github.com/hanifa-shaik/TrustVault/commit/add9413

## 2026-11-02: The permission code ended up in the wrong file (access control)

**What I asked:** For one central authorize() function plus download and delete routes.

**What it produced:** Instructions to put authorize() in permissions/__init__.py, add the routes to documents/__init__.py, and replace the dashboard page.

**What was wrong:** The instructions spread code over several files, and I pasted the authorize() block at the bottom of documents/__init__.py instead. The download and delete routes were missing, so the dashboard crashed with `BuildError: Could not build url for endpoint 'documents.download'`. A wrong paste like this is dangerous in an authorisation system, because the app can look fine while a check is not where I think it is.

**What I did instead:** I ran `findstr` to see which function was in which file, replaced documents/__init__.py with a complete version, and kept authorize() only in permissions/__init__.py. Then I tested the important case: a second owner pasting the first owner's download link gets 404, and the attempt shows as a denied row in the audit log.

**Commit:** https://github.com/hanifa-shaik/TrustVault/commit/1738ca1

## 2026-11-04: A command printed my secret key (secrets)

**What I asked:** For a secret key to use when deploying.

**What it produced:** A Python command that printed a 64-character key to the terminal. I photographed my screen and sent it, so the key was exposed.

**What was wrong:** A secret must never appear in a photo or chat. The command printed it instead of copying it somewhere safe.

**What I did instead:** I treated that key as used up and never deployed it. I wrote a new one into a file that Git ignores, copied it from there, and later let Render generate the key that is actually live. I also run `cls` before photographing the terminal.

**Commit:** none. This was a settings change on Render, not code.

## 2026-11-05: The AI claimed a disabled user's login would stay valid (access control)

**What I asked:** For the next steps to harden access control after deployment.

**What it produced:** A plan saying a disabled user's existing login would keep working, and that my new test would fail until I fixed it.

**What was wrong:** The claim was never checked. I wrote the test first, and it passed (42 passed), because Flask-Login already treats a disabled user as logged out. The AI had described a security gap that did not exist.

**What I did instead:** I kept the test as protection against future breakage, and added an explicit active check to the user loader as defence in depth. I also wrote a second test where an admin disables a user and that user's next request is refused.

**Commit:** https://github.com/hanifa-shaik/TrustVault/commit/3fe71ab (the test) and https://github.com/hanifa-shaik/TrustVault/commit/9549bb2 (the user loader check and the admin test)

## 2026-11-05: The first audit log could detect tampering but not prevent it (audit trail)

**What I asked:** For an audit trail that nobody can quietly alter.

**What it produced:** A hash-chained log, where each row stores the hash of the row before it, and a verify function. My test showed that editing a row was detected. The AI said at the time that this was tamper-evident, not tamper-proof.

**What was wrong:** The brief asks what stops someone changing the log. A hash chain only detects a change afterwards. Anyone with database access could still edit or delete rows, and two requests arriving at the same moment could fork the chain.

**What I did instead:** I added PostgreSQL triggers that refuse UPDATE, DELETE and TRUNCATE on the audit table, and a database lock so only one request writes at a time. I checked it on the live Neon database: my UPDATE statement failed with `audit_log is append-only`, and the integrity check on the admin page still passed afterwards. The triggers and the lock only work on PostgreSQL, so the automated tests (which use SQLite) do not cover them. I recorded that as a known gap in THREATS.md.

**Commit:** https://github.com/hanifa-shaik/TrustVault/commit/44731f4 (the audit guards and the lock) and https://github.com/hanifa-shaik/TrustVault/commit/9549bb2 (installing the guards when the app starts)

## Prompts and instructions I reused

- **My opening prompt to ChatGPT:** a request for a 7-day plan and technology choices for TrustVault. The plan (Flask, PostgreSQL, SQLAlchemy, Flask-Login, pytest, Render) is what I started from.
- **Context I gave Claude:** the TrustVault problem statement, the Snovasys instructions page, and the ChatGPT plan.
- **My standing instruction to Claude:** I know very little, so guide me step by step in detail, one module at a time, with what I should see after each step. I run the code and paste back errors and screenshots, and do not invent PROMPTS.md entries.
- **The "remove one check" experiment:** a method I repeated four times. I deleted one security check, ran the tests, confirmed they failed, and undid the change with git. Removing the authorize() call from `load_or_404` made 14 tests fail. Removing the owner check made 8 fail. Removing the revoked-grant filter made 1 fail. Removing the admin gate made 2 fail.