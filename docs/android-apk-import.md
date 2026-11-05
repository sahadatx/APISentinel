# Android APK metadata import

For `ANDROID_API` or `BOTH` assessments, an analyst with assessment write access can submit a multipart upload to:

```text
POST /api/v1/assessments/{assessment_id}/android-applications/apk
multipart field: apk
```

The limit is 20 MiB. The API forwards bytes to the Compose `apk-parser` service, which is attached only to the `parser-internal` network shared with the API. It has no host-published port or external network route, runs as UID 10002, has a read-only root filesystem, drops capabilities, disables privilege escalation, and is limited to 192 MiB, 0.5 CPU, 32 processes and two concurrent requests. API calls use a 2-second connect timeout and bounded 12-second HTTPX operation timeouts. Parser failures are returned as sanitized errors.

The parser does not extract archive members or execute APK code. It bounds ZIP entry count, declared expanded size, manifest size, compression ratio and XML attributes; rejects path traversal names and XML DTD/entity declarations; reads only `AndroidManifest.xml`; then extracts package, version and SDK values. It supports text and Android binary XML manifests. A manifest-only static adapter also records declared debuggable/backup/cleartext flags, exported or intent-filter components, and permissions as `REVIEW_REQUIRED` observations. It never creates a vulnerability finding automatically. The API stores only sanitized metadata, a SHA-256 of the entire uploaded APK and an audit event. APK bytes are never stored. Duplicate package records are rejected.

The parser runs in a restricted container but shares the host kernel; this is process/container isolation, not a VM boundary. Keep its internal network private and avoid granting it host mounts or Docker socket access. A parser compromise may affect the parser container and internal network segment; the service is intentionally given no credentials, database, writable persistent volume or public egress.

The output proves only the supplied file's hash and parsed manifest values. It does not verify the publisher signature, APK authenticity, device provenance, API hosts, certificate pinning behavior or legal authorization. Declared app domains never authorize a target. Imported endpoints still require normal assessment scope and independent review. For mobile traffic inventory, use the documented structured Burp JSON import; its app/device origin is not authenticated.

The local tests use synthetic APK archives, including a synthetic binary Android XML manifest. The live sidecar must be built and available in Compose; a local API process with no `APISENTINEL_APK_PARSER_URL` fails closed with 503.
