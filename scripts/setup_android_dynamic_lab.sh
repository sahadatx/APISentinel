#!/usr/bin/env bash
set -euo pipefail

# Create a dedicated, rootable Android 11 Google APIs AVD for authorized lab work.
# This script does not install a client APK, connect to a target API, or start tests.

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}}"
AVD_NAME="APISentinel_API30"
SYSTEM_IMAGE="system-images;android-30;google_apis;x86_64"
SDKMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/sdkmanager"
AVDMANAGER="$SDK_ROOT/cmdline-tools/latest/bin/avdmanager"
EMULATOR="$(command -v emulator || true)"
ADB="$(command -v adb || true)"

if [[ ! -x "$SDKMANAGER" || ! -x "$AVDMANAGER" ]]; then
  echo "Android command-line tools are missing under $SDK_ROOT/cmdline-tools/latest." >&2
  echo "Install the official Android command-line tools and accept their SDK licenses, then rerun." >&2
  exit 2
fi
if [[ -z "$EMULATOR" || -z "$ADB" ]]; then
  echo "Android emulator and adb must be installed and available in PATH." >&2
  exit 2
fi
if [[ ! -r /dev/kvm ]]; then
  echo "KVM is unavailable. Configure hardware virtualization before starting this AVD." >&2
  exit 2
fi

"$SDKMANAGER" --sdk_root="$SDK_ROOT" "platform-tools" "platforms;android-30" "$SYSTEM_IMAGE"

if ! "$EMULATOR" -list-avds | grep -Fxq "$AVD_NAME"; then
  printf 'no\n' | "$AVDMANAGER" create avd --force --name "$AVD_NAME" \
    --package "$SYSTEM_IMAGE" --device "pixel_4"
fi

if "$ADB" devices | awk 'NR > 1 {print $1}' | grep -Fxq 'emulator-5554'; then
  echo "emulator-5554 is already attached; stop it before using this lab profile." >&2
  exit 3
fi

"$EMULATOR" -avd "$AVD_NAME" -no-window -no-audio -no-boot-anim \
  -no-snapshot-load -no-snapshot-save -port 5554 \
  >"${TMPDIR:-/tmp}/apisentinel-android-emulator.log" 2>&1 &
EMULATOR_PID=$!
trap 'kill "$EMULATOR_PID" 2>/dev/null || true' EXIT

for _ in $(seq 1 180); do
  if "$ADB" -s emulator-5554 get-state >/dev/null 2>&1 && \
     [[ "$("$ADB" -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == "1" ]]; then
    break
  fi
  sleep 2
done
if [[ "$("$ADB" -s emulator-5554 shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" != "1" ]]; then
  echo "Android AVD did not finish booting; see ${TMPDIR:-/tmp}/apisentinel-android-emulator.log" >&2
  exit 4
fi

# This is a dedicated lab profile; keep its general network disabled until an
# assessment-specific, authorized runtime network policy is configured.
"$ADB" -s emulator-5554 shell svc wifi disable >/dev/null 2>&1 || true
"$ADB" -s emulator-5554 shell svc data disable >/dev/null 2>&1 || true

echo "Android lab AVD is booted as emulator-5554 (API 30). No app was installed or tested."
echo "Emulator PID: $EMULATOR_PID"
trap - EXIT
