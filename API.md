# API: who may call what

Every route except login and register needs a logged-in session. "Owner of document" means the person who uploaded it. Refusals return 404, not 403, so nobody can tell which documents exist. All POST routes need a CSRF token.

| Method | Path | Who is allowed |
|---|---|---|
| GET, POST | /register | Anyone not logged in. Roles owner or viewer only |
| GET, POST | /login | Anyone. Blocked after repeated failures (429) |
| POST | /logout | Any logged-in user |
| GET | /dashboard | Any logged-in user. Shows only documents they may read. Admins are sent to /admin |
| GET, POST | /upload | Users with role owner |
| GET | /documents/<id>/download | Owner of the document, or a person with a read or edit grant |
| GET, POST | /documents/<id>/edit | Owner of the document, or a person with an edit grant |
| POST | /documents/<id>/delete | Owner of the document only |
| GET | /documents/<id>/share | Owner of the document only |
| POST | /documents/<id>/grant | Owner of the document only |
| POST | /documents/<id>/revoke/<grant_id> | Owner of the document only |
| GET | /admin/ | Admin only |
| GET | /admin/audit | Admin only |
| POST | /admin/verify | Admin only |
| POST | /admin/users/<id>/toggle | Admin only (not on admins or themselves) |