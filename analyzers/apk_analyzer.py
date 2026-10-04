import re
import zipfile


class APKAnalyzer:
    """Analyze Android APK files - manifest, permissions, and structure.
    Works with zipfile since APK is a ZIP container."""

    DANGEROUS_PERMISSIONS = {
        "android.permission.READ_CONTACTS": "Reads user contacts (privacy)",
        "android.permission.WRITE_CONTACTS": "Modifies user contacts",
        "android.permission.READ_SMS": "Reads SMS messages (phishing/data theft)",
        "android.permission.RECEIVE_SMS": "Receives SMS (2FA interception)",
        "android.permission.SEND_SMS": "Sends SMS (premium SMS fraud)",
        "android.permission.READ_CALL_LOG": "Reads call history (privacy)",
        "android.permission.READ_PHONE_STATE": "Reads phone state/IMEI (device fingerprinting)",
        "android.permission.RECORD_AUDIO": "Records audio (eavesdropping)",
        "android.permission.CAMERA": "Accesses camera (spying)",
        "android.permission.ACCESS_FINE_LOCATION": "Precise GPS location (tracking)",
        "android.permission.ACCESS_COARSE_LOCATION": "Approximate location (tracking)",
        "android.permission.GET_ACCOUNTS": "Accesses device accounts",
        "android.permission.READ_EXTERNAL_STORAGE": "Reads external storage (data theft)",
        "android.permission.SYSTEM_ALERT_WINDOW": "Overlay windows (clickjacking)",
        "android.permission.PACKAGE_USAGE_STATS": "Usage statistics (spying)",
        "android.permission.REQUEST_INSTALL_PACKAGES": "Install unknown apps (malware distribution)",
        "android.permission.WAKE_LOCK": "Keeps device awake (battery drain)",
        "android.permission.ACCESS_WIFI_STATE": "WiFi state (network reconnaissance)",
        "android.permission.CHANGE_WIFI_STATE": "Changes WiFi state",
        "android.permission.USE_CREDENTIALS": "Uses stored credentials",
        "android.permission.INTERNET": "Network access (C2 communication)",
    }

    SOFTWARE_SIGNATURES = {
        "AppLock": "AppLocker",
        "NotificationService": "Notification spyware",
        "WifiService": "WiFi manipulation",
        "AccessControl": "Access control manipulation",
        "AccessibilityService": "Accessibility abuse (can read all screen content)",
        "OverlayService": "Overlay attacks (clickjacking)",
        "VpnService": "VPN interception",
    }

    def __init__(self, file_path):
        self.file_path = file_path
        self.data = None

    def analyze(self):
        """Extract and analyze APK contents."""
        try:
            with zipfile.ZipFile(self.file_path, "r") as zf:
                names = zf.namelist()
                manifest = None
                if "AndroidManifest.xml" in names:
                    manifest = zf.read("AndroidManifest.xml")

                dex_files = [n for n in names if n.endswith(".dex")]
                so_files = [n for n in names if n.endswith(".so")]
                asset_files = [n for n in names if n.startswith("assets/")]

                file_list = self._analyze_files(zf, names)
                suspicious_code = self._find_suspicious_code(zf, names)
        except zipfile.BadZipFile:
            return {"error": "Not a valid APK/ZIP file"}

        if manifest is None:
            manifest_text = ""
            manifest_data = self._extract_text_from_manifest(zf)
        else:
            manifest_text = self._decode_manifest(manifest)
            manifest_data = self._decode_manifest(manifest)

        permissions = self._extract_permissions(manifest_text or manifest_data)
        package_name = self._extract_package_name(manifest_text or manifest_data)
        activities = self._extract_activities(manifest_text or manifest_data)
        services = self._extract_services(manifest_text or manifest_data)

        dangerous_perms = [
            {"permission": p, "reason": self.DANGEROUS_PERMISSIONS[p]}
            for p in permissions if p in self.DANGEROUS_PERMISSIONS
        ]

        return {
            "is_valid": True,
            "package_name": package_name,
            "permissions": permissions,
            "all_permissions": sorted(permissions),
            "permission_count": len(permissions),
            "dangerous_permissions": dangerous_perms,
            "activities": activities,
            "services": services,
            "dex_files": dex_files,
            "native_libraries": so_files,
            "asset_count": len(asset_files),
            "total_entries": len(names),
            "file_suspicious": file_list,
            "suspicious_code": suspicious_code,
            "manifest_plain": manifest is None or self._check_debuggable(manifest_text or manifest_data),
        }

    def _decode_manifest(self, data):
        """Decode binary AndroidManifest.xml (AXML format) string pool."""
        if not data or len(data) < 8:
            return ""
        try:
            return self._extract_binary_strings(data)
        except Exception:
            return self._extract_readable(data)

    def _extract_binary_strings(self, data):
        """Extract strings from AXML string pool."""
        import struct

        if len(data) < 28:
            return ""

        # String pool chunk header
        chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, 0)
        if chunk_type != 0x0001:
            # Skip to find string pool chunk (skip XML start element)
            offset = 0
            while offset + 8 <= len(data):
                ctype, hsize, csize = struct.unpack_from("<HHI", data, offset)
                if ctype == 0x0001:
                    break
                offset += csize if csize else 8
            if offset + 28 > len(data):
                return self._extract_readable(data)
            chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, offset)

        if len(data) < offset + 28:
            return self._extract_readable(data)

        (string_count, _style_count, flags, strings_start, _styles_start) = struct.unpack_from(
            "<IIIII", data, offset + 8
        )

        is_utf8 = bool(flags & 0x00000100)

        strings = []
        for i in range(min(string_count, 4000)):
            off_pos = offset + header_size + i * 4
            if off_pos + 4 > len(data):
                break
            (str_offset,) = struct.unpack_from("<I", data, off_pos)
            abs_pos = offset + strings_start + str_offset
            if abs_pos >= len(data):
                continue
            try:
                if is_utf8:
                    s = self._read_utf8_string(data, abs_pos)
                else:
                    s = self._read_utf16_string(data, abs_pos)
                if s:
                    strings.append(s)
            except Exception:
                continue

        joined = "\n".join(strings)
        return joined

    def _read_utf8_string(self, data, pos):
        """Read an AXML UTF-8 string at pos."""
        length = self._read_length(data, pos)
        return data[pos:pos + length].decode("utf-8", errors="ignore")

    def _read_utf16_string(self, data, pos):
        """Read an AXML UTF-16 string at pos (16-bit chars until null)."""
        chars = []
        p = pos
        while p + 2 <= len(data):
            val = struct.unpack_from("<H", data, p)[0]
            if val == 0:
                break
            chars.append(chr(val))
            p += 2
            if len(chars) > 4096:
                break
        return "".join(chars)

    def _read_length(self, data, pos):
        """Read AXML encoded length (1 or 2 bytes)."""
        first = data[pos]
        if first & 0x80:
            second = data[pos + 1]
            return ((first & 0x7F) << 8) | second
        return first

    def _extract_readable(self, data):
        """Fallback: strip non-printable bytes."""
        return re.sub(rb"[^\x20-\x7e]", b"\n", data).decode("utf-8", errors="ignore")

    def _extract_text_from_manifest(self, zf):
        """Fallback: extract readable text as-is."""
        try:
            data = zf.read("AndroidManifest.xml")
            return re.sub(rb"[^\x20-\x7e]", b" ", data).decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def _extract_package_name(self, text):
        if not text:
            return "Unknown (binary manifest)"
        match = re.search(r'package="([^"]+)"', text)
        if match:
            return match.group(1)
        return "Unknown"

    def _extract_permissions(self, text):
        if not text:
            return []
        return set(re.findall(r'uses-permission[^>]*name="([^"]+)"', text))

    def _extract_activities(self, text):
        if not text:
            return []
        return re.findall(r'activity[^>]*name="([^"]+)"', text)

    def _extract_services(self, text):
        if not text:
            return []
        return re.findall(r'service[^>]*name="([^"]+)"', text)

    def _analyze_files(self, zf, names):
        """Look for suspicious files inside the APK."""
        suspicious = []
        for name in names:
            lower = name.lower()
            if any(key in lower for key in
                   ("root", "su", "superuser", "tamper", "hook", "dex2jar",
                    "readelf", "objdump", "ptrace")):
                suspicious.append(name)
        return suspicious

    def _find_suspicious_code(self, zf, names):
        """Look for suspicious code patterns in DEX and asset files."""
        findings = []
        for name in names:
            if name.endswith(".dex") or name.endswith(".js") or name.endswith(".smali"):
                try:
                    data = zf.read(name)
                except Exception:
                    continue
                lower = data.lower()
                checks = {
                    b"cryptolib": "Crypto operations",
                    b"reflection": "Reflective code (obfuscation)",
                    b"classloader": "Dynamic class loading",
                    b"webview": "WebView usage (possible phishing)",
                }
                if b"cryptolib" in lower or b"crypto" in lower or b"aes" in lower:
                    findings.append({"file": name, "finding": "Crypto operations"})
                if b"reflection" not in lower and b"reflect" in lower:
                    findings.append({"file": name, "finding": "Reflective code (obfuscation)"})
                if b"classloader" in lower:
                    findings.append({"file": name, "finding": "Dynamic class loading"})
                if b"webview" in lower:
                    findings.append({"file": name, "finding": "WebView usage (possible phishing)"})
                if b"accessibilityservice" in lower:
                    findings.append({"file": name, "finding": "AccessibilityService (screen reading)"})
                if b"smssender" in lower or b"sendsms" in lower:
                    findings.append({"file": name, "finding": "SMS sending functionality"})
                if b"/system/bin/su" in lower:
                    findings.append({"file": name, "finding": "Root check/attempt"})
        return findings

    def _check_debuggable(self, text):
        if not text:
            return True
        return "android:debuggable=\"true\"" in text