# TrustVault - Security Threats

Potential security risks and planned protections.

1. Unauthorized document access.
   - Protection: Role-based access control.

2. Password theft.
   - Protection: Store hashed passwords, never plain-text passwords.

3. Cross-site request forgery (CSRF).
   - Protection: Use Flask-WTF CSRF protection.

4. Malicious file uploads.
   - Protection: Validate file types and file sizes.