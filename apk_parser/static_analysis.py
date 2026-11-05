"""Manifest-only Android static review adapter; emits observations, not findings."""


class AndroidManifestStaticAnalysisAdapter:
    version = "1.0.0"

    @staticmethod
    def _boolean(value):
        if isinstance(value, bool):
            return value
        normalized = str(value or "").strip().lower()
        if normalized in {"true", "1"}:
            return True
        if normalized in {"false", "0"}:
            return False
        return None

    def analyze(self, manifest):
        application = manifest.get("application", {})
        checks = []
        for key, check_id, label in (
            ("debuggable", "android.debuggable", "Debuggable build flag"),
            ("allowBackup", "android.backup_policy", "Backup policy declaration"),
            ("usesCleartextTraffic", "android.cleartext_traffic", "Cleartext traffic declaration"),
        ):
            raw = application.get(key)
            parsed = self._boolean(raw)
            state = "NOT_DECLARED" if raw is None else (
                "DECLARED_ENABLED" if parsed is True else
                "DECLARED_DISABLED" if parsed is False else "UNRESOLVED")
            checks.append({
                "id": check_id,
                "label": label,
                "state": state,
                "declared_value": raw if parsed is not None else None,
                "interpretation": "Manifest declaration only; review against release, backup, and network policy. This is not a confirmed vulnerability.",
            })

        exported = []
        for component in manifest.get("components", [])[:50]:
            has_filter = bool(component.get("intent_filter"))
            raw = component.get("exported")
            parsed = self._boolean(raw)
            state = ("EXPLICITLY_EXPORTED" if parsed is True else
                     "EXPLICITLY_NOT_EXPORTED" if parsed is False else
                     "PLATFORM_DEFAULT_REQUIRES_REVIEW" if has_filter else "NOT_DECLARED")
            if parsed is True or has_filter:
                exported.append({
                    "type": component.get("type", "component"),
                    "name": str(component.get("name", ""))[:120],
                    "state": state,
                    "intent_filter": has_filter,
                })

        permissions = sorted({str(value)[:120] for value in manifest.get("permissions", [])
                              if isinstance(value, str) and value})[:50]
        return {
            "adapter": "android-manifest-static",
            "version": self.version,
            "scope": "AndroidManifest.xml only; no DEX, resources, native libraries, signing, or runtime inspection",
            "review_state": "REVIEW_REQUIRED",
            "checks": checks,
            "exported_components": exported,
            "declared_permissions": permissions,
            "limitations": [
                "Observations are static manifest metadata, not confirmed vulnerabilities.",
                "No APK code was extracted, decompiled, executed, or sent to a dynamic-analysis tool.",
                "Manifest declarations do not establish runtime behavior or actual data exposure.",
            ],
        }
