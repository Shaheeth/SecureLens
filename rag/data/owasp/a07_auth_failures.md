# OWASP A07:2021 - Identification and Authentication Failures

## Summary
Confirmation of a user's identity, authentication, and session
management is critical for protecting against authentication-related
attacks. Weaknesses include permitting weak/default passwords, exposing
session identifiers in URLs, not invalidating session IDs after logout,
missing or ineffective multi-factor authentication, and comparing
credentials using non-constant-time operations.

## Prevention
- Implement multi-factor authentication where possible.
- Never ship or deploy with default credentials.
- Use constant-time comparison (`hmac.compare_digest`) when comparing
  secrets/tokens to prevent timing attacks.
- Enforce strong password policies and check against known-breached
  password lists (e.g. via the "Have I Been Pwned" API pattern).
- Rotate and invalidate session identifiers after login and logout.

## Related CWEs
CWE-287 (Improper Authentication), CWE-306 (Missing Authentication for
Critical Function), CWE-798 (Use of Hardcoded Credentials)
