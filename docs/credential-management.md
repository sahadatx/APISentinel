# Credential profile management

APISentinel supports one assessment-bound bearer profile for bounded transport requests. The registered security checks still declare unauthenticated behavior and will not run against endpoints marked as requiring authentication. Never use this profile as general API access or put a token in an assessment note, imported specification, report, or TestRun body.

## Initialize

1. For development only, generate a protected Fernet key file with `apisentinel generate-credential-key --path /private/location/apisentinel-credentials.env` and set `APISENTINEL_CREDENTIAL_ENCRYPTION_PROVIDER=fernet`.
2. For staging/production, set `APISENTINEL_CREDENTIAL_ENCRYPTION_PROVIDER=aws_kms`, provide `APISENTINEL_CREDENTIAL_KMS_KEY_ID` and `APISENTINEL_CREDENTIAL_KMS_REGION`, and run with an AWS workload identity. Grant only `kms:GenerateDataKey` and `kms:Decrypt` on the selected symmetric KMS key; do not inject static AWS access keys. Configure SDK region and credentials via the deployment identity mechanism.
3. Back up the KMS key policy/configuration separately from the database. A database snapshot without decrypt permission and a recoverable KMS key cannot restore secrets.
4. Use the authenticated owner API `PUT /api/v1/assessments/{id}/credential-profile` with `{"token":"..."}`. Fernet mode stores Fernet ciphertext. AWS KMS mode uses KMS-generated per-record data keys and AES-256-GCM; the encrypted data key and ciphertext are stored, never plaintext. `GET` reports status; `DELETE` revokes the profile.
5. Mark the imported endpoint as authentication-required and explicitly approve it. For a bounded HTTP request, the server resolves the assessment's own active profile; clients cannot choose another assessment's profile ID.

The ciphertext, never the plaintext token, is stored in the database. KMS mode binds envelope encryption with an authenticated purpose context and reuses the AWS SDK's workload identity. Profile creation/update/revocation is audited without token material. Each request re-resolves the profile before outbound hops, and the runner strips bearer credentials when a redirect changes origin. TOTP authenticator seeds use the same provider with a separate encryption purpose context.

## Rotate the key

Stop all API workers and take a verified database backup. Fernet rotation uses `APISENTINEL_CREDENTIAL_ENCRYPTION_KEY_NEXT`. AWS KMS rotation uses `APISENTINEL_CREDENTIAL_KMS_KEY_ID_NEXT`; the identity must be permitted to decrypt old ciphertext and generate data keys under both keys. Run `apisentinel rotate-credential-key` once. It re-encrypts bearer profiles and MFA seeds in one database transaction and prints only a row count. After success, update the primary provider key ID, restart workers, then verify profile resolution and MFA sign-in. Keep the old KMS key and its decrypt permission until the backup retention window expires. The database transaction rolls back on any encryption/decryption error.

Rotation requires exclusive maintenance: do not run API workers during the command. Losing the active key without a matching backup is unrecoverable. AWS KMS mode has been mock-tested locally, but this workspace has no AWS account, KMS key, workload identity, or IAM policy to perform a live cloud round-trip. KMS provides per-record data-key envelope encryption; zero-downtime rotation is not supported.

## Recovery and limitations

Restore the database and matching key as a pair. If only the encryption key is lost, stored secrets cannot be reconstructed and each profile must be replaced by an authorized operator. Revocation blocks subsequent resolver lookups; it cannot retract a request already sent. The credential-management endpoints are also available in the assessment cards; tokens are password-masked while entered and cleared from UI state after save.
