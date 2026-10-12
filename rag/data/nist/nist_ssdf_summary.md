# NIST SP 800-218 (Secure Software Development Framework) - Summary

Original summary for grounding purposes; consult the authoritative NIST
publication for compliance use.

NIST's Secure Software Development Framework (SSDF) organizes secure
development practices into four groups:

1. **Prepare the Organization (PO)** — define security requirements,
   roles, and toolchains before development starts.
2. **Protect the Software (PS)** — protect all components of the
   software from tampering and unauthorized access, including source
   code repositories and build pipelines.
3. **Produce Well-Secured Software (PW)** — design, review, and test
   software to minimize security vulnerabilities, including static
   analysis (SAST), code review, and threat modeling. This is the
   category SecureLens AI most directly supports: automated static
   analysis (PW.7) and vulnerability remediation (PW.8/PW.9-adjacent
   guidance).
4. **Respond to Vulnerabilities (RV)** — identify and remediate
   vulnerabilities on an ongoing basis, including triage, root-cause
   analysis, and verifying that fixes actually resolve the issue
   (which SecureLens AI implements via automatic re-scan after
   AI-generated fixes).

## Relevant NIST guidance referenced by SecureLens AI
- **NIST SP 800-53** — control families for access control (AC),
  identification & authentication (IA), and system/communications
  protection (SC) inform the AUTH_WEAKNESS and crypto findings.
- **NIST SP 800-63B** — digital identity guidelines, referenced for
  authentication weakness remediation advice (e.g. avoid weak secret
  comparison, enforce strong credential storage).
- **NIST Cybersecurity Framework (CSF) 2.0** — the "Identify" and
  "Protect" functions align with SecureLens AI's detection and
  remediation-recommendation workflow.
