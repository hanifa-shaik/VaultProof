# AI Prompts Used

This file records the AI prompts used during the development of TrustVault.

## Development Assistance
- Project setup and Flask configuration.
- Database design and user authentication.
- Security improvements and testing.
# PROMPTS.md

## 2026-11-02: Day 1, templates folder in the wrong place

**What I asked:** I asked the AI to guide me step by step to build
registration and login for TrustVault in Flask.

**What it produced:** Code for auth/__init__.py, app.py and four HTML
files (base, register, login, dashboard), with instructions to put the
HTML files in a folder called `templates`.

**What went wrong:** When I ran the app, Chrome showed
`jinja2.exceptions.TemplateNotFound: login.html`. My `templates` folder
had ended up inside the `auth` folder, but Flask looks for it next to
app.py. The AI's first fix (check the folder names) did not solve it,
and dragging the folder in VS Code did not work for me either.

**What I did instead:** I used the terminal command
`Move-Item auth\templates templates` to move the folder next to app.py.
The login page then loaded.

**Commit:** https://github.com/hanifa-shaik/TrustVault/commit/750ee8633b6284958974e171600fb50b0b39d39b

**What I learned:** Flask finds templates by folder location, so where
a file lives matters, not just what is inside it.

## 2026-11-05: AI claimed a disabled user's session would stay valid

**What I asked:** I asked the AI for the next hardening steps for access control.

**What it produced:** A plan saying a disabled user's existing login would keep working, and that my test would fail until I fixed it.

**What was wrong:** The claim was never checked. I wrote the test first. It passed (42 passed), because Flask-Login already treats a disabled user as logged out. The AI had stated an authorisation gap that did not exist.

**What I did instead:** I kept the test as a guard against future breakage, and kept an explicit active check in the user loader as defence in depth.

**Commit:** https://github.com/hanifa-shaik/TrustVault/commit/3fe71ab26247dfeee4912a72f2d0094f1d5ec01a