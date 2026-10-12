# OWASP A10:2021 - Server-Side Request Forgery (SSRF)

## Summary
SSRF flaws occur when a web application fetches a remote resource
without validating the user-supplied URL, allowing an attacker to coerce
the application into sending a crafted request to an unexpected
destination, even when protected by a firewall, VPN, or another type of
network access control list (ACL). Cloud metadata endpoints
(e.g. 169.254.169.254) are a frequent high-impact target.

## Prevention
- Validate and sanitize all client-supplied input used to build outbound
  requests; use an allow-list of permitted schemes, hosts, and ports.
- Disable HTTP redirects when fetching a user-controlled URL, or
  re-validate the destination after following a redirect.
- Segment remote resource access functionality onto separate networks
  and deny requests to internal/link-local address ranges
  (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, etc.) by default.
- Never send raw error/response details from the internal fetch back to
  the end user (limits information disclosure).

## Related CWEs
CWE-918 (Server-Side Request Forgery)
