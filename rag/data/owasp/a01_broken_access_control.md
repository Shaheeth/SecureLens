# OWASP A01:2021 - Broken Access Control

## Summary
Access control enforces policy such that users cannot act outside of
their intended permissions. Failures typically lead to unauthorized
information disclosure, modification, or destruction of data, or
performing a business function outside the user's limits. Path
traversal — accessing files/directories stored outside the intended
folder via sequences like `../../etc/passwd` — is a common manifestation.

## Prevention
- Deny by default; enforce record ownership checks rather than trusting
  that a user can only reach records they're authorized for via the UI.
- Normalize and validate file paths against a known-safe base directory
  (`os.path.realpath` + prefix check) before performing file operations.
- Rate limit API and controller access to minimize harm from automated
  attack tooling.
- Log access control failures and alert admins on repeated failures.

## Related CWEs
CWE-22 (Path Traversal), CWE-284 (Improper Access Control), CWE-285
(Improper Authorization)
