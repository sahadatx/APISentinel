# External security tool result import

## Supported format

The first versioned findings adapter is `burp_scanner_issues_xml` v1 for the Burp Suite Professional Scanner issues XML export. It is distinct from the existing Burp HTTP-history JSON inventory importer. MobSF exports, Burp project files, and arbitrary XML/JSON exports are not supported by this adapter.

## Use

1. In **Findings**, choose **Import Burp results**.
2. Select the authorized client assessment that owns the report.
3. Choose the saved Burp Scanner issues XML file (maximum 5 MiB, 500 issue entries).
4. Confirm the import. APISentinel displays counts for imported findings and exact duplicates skipped.
5. Open each imported finding and validate its evidence and relevance before triage.

The API is `POST /api/v1/findings/import/burp-scanner-xml?assessment_id=<id>` with multipart field `document`. It uses the existing authenticated analyst route and client access checks. It does not start scans, send HTTP requests, or create test runs.

## Provenance and lifecycle

Findings use the existing canonical `Finding` table. Evidence records source format, adapter ID/version, Burp export version where present, artifact SHA-256, external serial number/type, source severity/confidence, sanitized host/path/method, import time, and whether raw messages were discarded. A matching current endpoint is linked only when host, method, and path match exactly. Query strings and fragments are omitted. Request and response messages are not retained.

Every imported issue is `Candidate`, `PENDING_VALIDATION`, `UNASSESSED`, and `OPEN` for remediation. Burp severity maps to the equivalent APISentinel severity label as an analyst triage hint; imported output is never treated as APISentinel validation. Duplicate issues from the identical artifact are skipped. Import and per-finding audit events are stored in the existing audit table in the same transaction as finding creation.

## Safety and limits

The parser rejects entity declarations, strips the document type declaration before XML parsing, does not resolve external resources, limits input size and issue count, strips query/fragment data, and discards message content. It creates no execution work. The artifact digest identifies the exact imported file but does not independently prove the export's origin or authenticity. Analysts must review each item before making a finding or impact claim.

## Verification

Run `pytest -q tests/test_external_finding_import.py` and `cd dashboard && npm run build`.
