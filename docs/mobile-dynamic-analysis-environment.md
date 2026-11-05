# Mobile dynamic analysis environment

## Current verified state

- The workstation is Linux and has Android Emulator 36.1.9.0, ADB, Frida CLI 17.9.10, and `/dev/kvm`.
- A `Pixel_4` AVD definition exists, but its configured Android 11 Play Store system image is missing. It cannot boot.
- No Android device is currently attached to ADB.
- Official Android command-line tools are installed under `/home/kali/Android/Sdk/cmdline-tools/latest`; their Google-published SHA-256 was verified before extraction. The SDK license terms were accepted for this lab machine with the user's authorization.
- Android API 30 platform packages and the Google APIs system image are not installed. The official API 30 x86_64 image is 1,438,186,618 bytes; transfer tests returned only about 1 MiB in roughly 23 seconds, so its download was stopped rather than leave a multi-hour unmonitored transfer running.
- A dedicated `APISentinel_API30` AVD has not been created or booted. The existing `Pixel_4` AVD remains untouched.
- The APK/IPA metadata parser is separate and network-isolated. It does not run apps.
- Tailscale is the selected private network path for the future macOS runner, but this Linux workstation is not currently connected to a tailnet and no macOS runner endpoint has been registered.

### Verification record (2026-10-19)

- `scripts/setup_android_dynamic_lab.sh` syntax check: PASS (`bash -n`).
- Official command-line tools archive SHA-256: `4e4c464f145a7512b57d088ac6c278c03c9eea610886b35a5e0804e74eedf583` (matched before extraction).
- SDK manager currently sees Android Emulator 36.1.9 only; Android platform 30 and `system-images;android-30;google_apis;x86_64` are not installed.
- `emulator -list-avds` reports only the existing `Pixel_4`; `adb devices` reports no attached or running devices.
- Tailscale CLI is not installed and there is no tailnet connection or registered Mac runner.
- MobSF scan submission, Frida instrumentation, dynamic job persistence, or dynamic result import is not integrated into APISentinel yet.
- There is no macOS/iOS runtime runner attached to this Linux workstation.

## Dedicated Android lab profile

Use `ANDROID_SDK_ROOT=/home/kali/Android/Sdk scripts/setup_android_dynamic_lab.sh` after the API 30 packages are available. The script installs the API 30 Google APIs x86_64 image, creates a separate `APISentinel_API30` AVD, boots it headlessly, waits for boot completion, and disables Wi-Fi/mobile data. It does not install an application or send requests. The existing `Pixel_4` profile and its data remain untouched. The workstation already has the SDK command-line tools and accepted license receipts, so the remaining setup gate is the large image transfer.

The API 30 image transfer was attempted through the official SDK manager and range requests, but the measured transfer rate was too low for a responsible unattended install. Run the command above when a faster/reliable connection is available. Do not use a Play Store image for Frida work; use a dedicated Google APIs lab profile whose root/debug behavior can be verified.

Before connecting a client app, require current client authorization, a matching approved assessment scope, explicit analyst action, and a documented test identity. Keep network access disabled until an assessment-specific allowlist and egress policy is enforced. A transport or instrumentation event is not itself a finding; only validated observations with preserved evidence enter the finding workflow.

## Recommended Android runtime integration

The runtime worker should be a separate service from the API and from the metadata parser. It should accept only a registered AVD/device identifier and a persisted Android application record; never accept a shell command or user-provided Frida script. Provide a small fixed set of reviewed instrumentation profiles, such as process/package metadata and bounded network-security observations. Device installation, launch, capture, stop, cleanup, timeouts, cancellation, and evidence-size limits need explicit job states and audit events. The runtime worker must not inherit the general API runner's unrestricted network access.

## Recommended iOS runner connection

Use the user's selected **Tailscale VPN** as the private network path between a dedicated macOS runner and the APISentinel broker. The Mac agent should initiate an outbound connection over the tailnet; do not expose an inbound public port. Tailscale membership is transport isolation, not application authorization: still enforce a narrow tailnet ACL, mutual TLS or equivalent workload identity, short-lived device-bound credentials, and server-side authorization for every job. Do not use a shared chat secret or expose a general-purpose shell API.

The job envelope should bind the run to assessment ID, IPA hash/bundle ID, current authorization snapshot, approved test profile, expiry, and a cancellation token. The Mac agent should verify those claims before install/launch, return bounded sanitized results, and remove the app and temporary files after each run. Register the Mac runner and designated iPhone/iPad as explicit managed assets; revoke the runner identity and tailnet access when decommissioned.

APISentinel has no broker/agent protocol or macOS runner endpoint yet. Tailscale is the selected network path, but connection still requires this host and the Mac to join the intended tailnet, a reachable broker address on that tailnet, runner identity provisioning, iOS device UDID registration policy, and the supported instrumentation profiles. No iOS tests can run from this Linux host.

## Next implementation gates

1. Install the dedicated Android API 30 Google APIs image and boot the AVD.
2. Build the isolated runtime worker and fixed Frida profiles; integrate its persistent, cancellable job and audit lifecycle with APISentinel.
3. Add a MobSF static-analysis adapter as a separately isolated service; normalize its output as review-required observations and enforce artifact deletion/retention policy.
4. Define and deploy the authenticated macOS runner broker, then connect an iOS device.
5. Test only local fixtures or explicitly authorized client test builds; do not execute any dynamic run on metadata import or report generation.
