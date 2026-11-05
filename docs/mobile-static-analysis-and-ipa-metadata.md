# Mobile static metadata workflow

## Android APK

`POST /api/v1/assessments/{assessment_id}/android-applications/apk` accepts an APK up to 20 MiB for `ANDROID_API` or `BOTH` assessments. The API forwards the file to the private, network-isolated parser service. The parser reads the manifest without extracting or executing APK members. Its Android manifest adapter reports declared debuggable, backup and cleartext-traffic flags; exported or intent-filter components; and declared permissions. These are bounded static observations marked `REVIEW_REQUIRED`, not vulnerability findings. APK bytes are discarded after parsing; only metadata and the artifact SHA-256 are retained.

The adapter does not inspect DEX, resources, native libraries, signing certificates, embedded API secrets, device storage, TLS pinning, or runtime behavior. MobSF is not integrated. Frida and dynamic analysis are not integrated.

## iOS IPA

`POST /api/v1/assessments/{assessment_id}/ios-applications/ipa` accepts an IPA up to 50 MiB for mobile/combined assessments. It uses the same isolated parser service, reads exactly one `Payload/*.app/Info.plist`, and does not extract application members. It records the bundle ID, display name, version/build, minimum OS, selected bounded metadata, and whole-artifact SHA-256 in the assessment-scoped `ios_applications` table. IPA bytes are discarded.

This is metadata import only. It does not inspect executable code, entitlements, provisioning profiles, signatures, privacy manifests, device behavior, or iOS security. It is not an iOS VAPT result. Existing assessment types remain `ANDROID_API` and `BOTH`; the IPA feature is metadata attached to a mobile/combined engagement and does not add an iOS test engine.

## Safety, access and lifecycle

The parser has no database, credentials, public route, or target-network access. It runs on an internal Docker network. Compose pins its address to `172.24.0.2` so a host-run development API can reach it without publishing a parser port; the address is accepted only in development, test, or lab configuration. The Compose API uses the private `apk-parser:8090` service name. Start the parser with `docker compose up -d --build apk-parser` and verify `docker compose ps apk-parser` reports healthy. A host-run API needs `APISENTINEL_APK_PARSER_URL=http://172.24.0.2:8090` when it starts.

The API enforces the existing assessment/client access rules and records sanitized import audit events. Duplicate package/bundle IDs in one assessment return conflict. Migrations add only the iOS metadata table; APK metadata continues to use the existing Android table. Reports snapshot the imported metadata and identify the static/metadata-only limits.

## Not yet available

MobSF integration requires a separately isolated analysis worker, explicit file-retention policy, resource limits, task lifecycle, output sanitization and artifact-access controls. Frida or other dynamic analysis additionally requires an isolated device/emulator environment, authorized test accounts, controlled network egress and explicit user initiation. iOS runtime analysis also requires a compatible macOS/iOS device environment. These capabilities are not enabled; the current artifact UI must not be interpreted as MobSF, Frida, or runtime analysis.
