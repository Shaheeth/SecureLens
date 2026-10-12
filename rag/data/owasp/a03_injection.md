# OWASP A03:2021 - Injection

## Summary
Injection flaws occur when untrusted data is sent to an interpreter (SQL,
OS shell, LDAP, XPath, etc.) as part of a command or query. The attacker's
hostile data can trick the interpreter into executing unintended commands
or accessing data without proper authorization. SQL injection, OS command
injection, and cross-site scripting are the most common members of this
family, and injection has been in the OWASP Top 10 in every edition.

## Common Sources
- String concatenation or formatting used to build a query/command instead
  of parameterization.
- Dynamic ORM query construction from unsanitized input.
- Passing untrusted input directly into `os.system`, `subprocess` with
  `shell=True`, or similar OS-level interpreters.

## Prevention
- Use parameterized queries / prepared statements (never string-build SQL).
- Use an ORM with proper parameter binding and avoid raw query builders on
  untrusted input.
- Use an allow-list of permitted characters/commands for OS-level
  interactions; prefer APIs that avoid shell interpretation entirely
  (e.g. pass argument lists to subprocess rather than shell=True).
- Apply context-aware output encoding for HTML/JS/CSS/URL contexts to
  prevent XSS specifically.
- Enforce least privilege on database accounts used by the application.

## Related CWEs
CWE-89 (SQL Injection), CWE-78 (OS Command Injection), CWE-79 (XSS),
CWE-90 (LDAP Injection), CWE-943 (Improper Neutralization in NoSQL Queries)
