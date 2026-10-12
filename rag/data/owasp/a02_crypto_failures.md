# OWASP A02:2021 - Cryptographic Failures

## Summary
Formerly "Sensitive Data Exposure," this category focuses on failures
related to cryptography that often lead to exposure of sensitive data.
This includes transmitting data in cleartext, using outdated or weak
cryptographic algorithms, using default or weak keys, and not enforcing
encryption via security directives or headers.

## Common Weaknesses
- Use of broken/weak hash functions (MD5, SHA1) for password storage.
- Use of non-cryptographic pseudo-random number generators for tokens,
  session IDs, password reset codes, or API keys.
- Hardcoded encryption keys or secrets committed to source control.
- Missing TLS enforcement or use of deprecated protocol versions.

## Prevention
- Use modern password hashing (Argon2id, bcrypt, scrypt) with per-user
  salts and appropriate work factors — never fast general-purpose hashes.
- Use the `secrets` module (Python) or platform CSPRNGs for any
  security-relevant randomness, never `random`.
- Store keys/secrets in a secrets manager or environment configuration,
  rotate them regularly, and never hardcode them in source.
- Enforce TLS 1.2+ everywhere sensitive data is transmitted.

## Related CWEs
CWE-327 (Use of a Broken/Risky Cryptographic Algorithm), CWE-326
(Inadequate Encryption Strength), CWE-330 (Use of Insufficiently Random
Values), CWE-798 (Use of Hardcoded Credentials)
