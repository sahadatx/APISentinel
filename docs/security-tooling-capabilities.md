# Security tooling capability boundaries

This document describes verified APISentinel behavior, not a service promise. Tool output is evidence supplied by an analyst unless a named, gated integration is explicitly available.

| Capability | Current status | Scope and limits |
|---|---|---|
| CVSS | Implemented for analyst-entered findings | Accepts a complete CVSS v3.1 base vector and records its calculated base score in finding risk metadata and JSON/HTML/PDF/CSV reports. It does not calculate temporal/environmental scores, set technical severity, or validate a finding. |
| Burp Suite | Passive inventory and finding-result imports supported | API inventory accepts a bounded structured HTTP-history JSON subset. Findings accept the specific Burp Suite Professional Scanner issues XML export through APISentinel adapter `burp_scanner_issues_xml` v1 (5 MiB / 500 issue limits). Imported results preserve artifact SHA-256 and external issue provenance, remain Candidate / Pending Validation, and discard request/response messages. This is not Burp Pro automation or support for arbitrary Burp project exports. |
| Android APK | Implemented, manifest-only static observations | Reads bounded manifest metadata in a network-isolated parser and presents review-required observations. It does not inspect DEX/native code, execute the app, perform MobSF analysis, or provide Frida dynamic instrumentation. |
| iOS IPA | Implemented, metadata import only | Reads bounded `Info.plist` fields and stores the artifact hash and metadata. It does not perform iOS code, signature, entitlement, or runtime analysis. |
| MobSF | Not integrated | No service connection, scan lifecycle, normalized result adapter, or artifact retention workflow is present. |
| Frida / device dynamic testing | Not integrated | No isolated Android emulator/device worker or iOS/macOS runtime environment is configured. |
| Kiterunner and ffuf | Not implemented | No endpoint brute-force/fuzzing integration is present. Do not run these against a client target through APISentinel. |
| Custom scripts | Not implemented | APISentinel intentionally has no arbitrary script execution path. |
| POC and screenshots | Partial, analyst-authored evidence only | Sanitized JSON evidence and notes can be recorded. There is no dedicated screenshot/attachment store or automated POC capture. Never include credentials or customer secrets. |

Active integrations require a separate design for authorization freshness, scope enforcement, allowlisted methods/targets, process isolation, resource budgets, cancellation, evidence sanitization, and audit provenance. They must not be inferred from a report import or from a completed HTTP transport.

## Burp Scanner issues XML import

The Findings page supports a saved Burp Suite Professional Scanner issues XML export. The versioned APISentinel adapter accepts the documented `<issues>` / `<issue>` structure and supported severity, issue text, host, path, serial number, and optional request first-line method fields. The adapter strips the XML document type declaration before parsing, rejects entity declarations, caps imports at 500 findings and 5 MiB, and never resolves external resources. Request/response message elements are used only to infer a method when possible and are never persisted. Query strings and fragments are removed.

Imported rows use the canonical Finding model and retain adapter version, artifact digest, Burp export version, and external issue identifiers in finding evidence and audit metadata. The scanner's severity is retained as source metadata; the mapped local severity is a triage hint only. APISentinel confidence stays `UNASSESSED`, status stays `Candidate`, validation stays `PENDING_VALIDATION`, and remediation stays `OPEN`. Exact endpoint linking requires an existing current inventory endpoint with matching host, method, and path. Import is a file operation only: it creates no test run and sends no network request. Re-importing identical artifact issues skips duplicates. MobSF import is not currently supported.

API: `POST /api/v1/findings/import/burp-scanner-xml?assessment_id=<id>` with multipart field `document`. Use the Findings page's **Import Burp results** action, or send a multipart upload through the authenticated API. Invalid documents return 422; files above the limit return 413. Client access and analyst role checks run before parsing or persistence.

CVSS examples should be assigned only by an analyst who can justify every metric. The supplied severity field remains an independent technical classification. Report consumers should treat the CVSS base score as a prioritization aid, not as proof of exploitability or a substitute for business-impact review.
