# OWASP A08:2021 - Software and Data Integrity Failures

## Summary
This category covers code and infrastructure that does not protect
against integrity violations, notably insecure deserialization: taking
serialized/serializable data from an untrusted source and reconstructing
it into objects without validation, which can lead to remote code
execution, replay attacks, injection attacks, or privilege escalation.

## Common Weaknesses
- Using `pickle.load`/`pickle.loads` on data from an untrusted source
  (Python's pickle can execute arbitrary code during deserialization).
- Using `yaml.load()` without a `SafeLoader`, which can instantiate
  arbitrary Python objects from YAML content.
- Trusting client-side data (cookies, hidden form fields) without
  integrity verification (e.g. HMAC signature).

## Prevention
- Avoid native deserialization formats for untrusted data; prefer JSON.
- If you must deserialize complex objects, sign the payload (e.g. HMAC)
  and verify the signature before deserializing.
- Use `yaml.safe_load()` instead of `yaml.load()`.
- Verify software/dependency integrity (checksums, signed packages) in
  the CI/CD pipeline.

## Related CWEs
CWE-502 (Deserialization of Untrusted Data), CWE-345 (Insufficient
Verification of Data Authenticity)
