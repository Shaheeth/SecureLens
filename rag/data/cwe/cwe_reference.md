# CWE Quick Reference (SecureLens AI knowledge base)

Concise, original summaries of the CWE entries SecureLens AI maps findings
to. Full authoritative definitions live at https://cwe.mitre.org/ — this
file exists only to ground the local LLM's explanations.

## CWE-89: SQL Injection
Improper neutralization of special elements used in an SQL command allows
attacker-controlled input to alter query logic (e.g. bypass
authentication, exfiltrate or destroy data). Fix: parameterized queries.

## CWE-79: Cross-Site Scripting (XSS)
Improper neutralization of input during web page generation allows
attacker-supplied script to execute in a victim's browser session,
enabling session hijacking, defacement, or credential theft. Fix:
context-aware output encoding and auto-escaping templates.

## CWE-78: OS Command Injection
Improper neutralization of special elements used in an OS command allows
an attacker to execute arbitrary system commands. Fix: avoid shell
invocation with untrusted input; use argument-list APIs, not string
concatenation with shell=True.

## CWE-22: Path Traversal
Improper limitation of a pathname to a restricted directory allows
access to files/directories outside the intended folder via sequences
like `../`. Fix: canonicalize and validate paths against an allow-listed
base directory.

## CWE-798 / CWE-259: Use of Hardcoded Credentials
Software contains a hardcoded password, API key, or cryptographic key,
making it trivial to extract from source, binaries, or version control
history. Fix: externalize secrets to environment variables or a secrets
manager; rotate any secret that has ever been committed.

## CWE-327 / CWE-326: Broken or Weak Cryptography
Use of a cryptographic algorithm or key strength that is not sufficient
for the context (e.g. MD5/SHA1 for password hashing, small RSA key
sizes). Fix: use vetted modern algorithms (Argon2id/bcrypt for
passwords, AES-256-GCM for symmetric encryption).

## CWE-330: Use of Insufficiently Random Values
Use of a non-cryptographic PRNG (e.g. Python's `random` module) for a
security-sensitive value such as a session token or password reset code,
making the value predictable. Fix: use the `secrets` module or a
platform CSPRNG.

## CWE-502: Deserialization of Untrusted Data
Deserializing data from an untrusted source without validation can allow
an attacker to instantiate arbitrary objects or trigger code execution
(notably via Python `pickle` or unsafe YAML loading). Fix: prefer JSON,
or sign/verify data before deserializing with a native format.

## CWE-918: Server-Side Request Forgery (SSRF)
The web application fetches a remote resource without validating the
user-supplied URL, letting an attacker reach internal-only endpoints
(e.g. cloud metadata services). Fix: allow-list destinations, block
internal IP ranges, disable automatic redirect following.

## CWE-287 / CWE-306: Authentication Weaknesses
Improper or missing authentication for a critical function, allowing an
attacker to bypass identity verification, or comparing secrets with a
non-constant-time operation that leaks timing information. Fix: enforce
authentication consistently server-side; use `hmac.compare_digest`.
