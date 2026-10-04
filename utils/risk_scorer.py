class RiskScorer:
    """Risk scoring combining static analysis and Phase 2 specialized analyzers."""

    def __init__(self, phase1, advanced=None):
        self.phase1 = phase1
        self.advanced = advanced or {}

    def calculate(self):
        """Calculate a risk score from 0-100 and return details."""
        score = 0
        reasons = []
        stats = {}

        # ---- Phase 1: static analysis ----
        info = self.phase1.get("info", {})
        strings = self.phase1.get("strings", [])
        urls = self.phase1.get("urls", [])
        ips = self.phase1.get("ips", [])
        commands = self.phase1.get("commands", [])
        entropy = self.phase1.get("entropy", 0.0)

        if entropy > 7.5:
            score += 25
            reasons.append("Very high entropy detected - file may be packed or encrypted (common in malware)")
        elif entropy > 6.0:
            score += 12
            reasons.append("High entropy - possible compression or obfuscation")

        if commands:
            cmd_score = min(len(commands) * 8, 25)
            score += cmd_score
            reasons.append(f"Found {len(commands)} suspicious command indicators: {', '.join(commands[:4])}")

        if urls:
            score += min(len(urls) * 5, 15)
            reasons.append(f"Found {len(urls)} URL(s) in the file (possible C2 communication)")
        if ips:
            score += min(len(ips) * 3, 10)
            reasons.append(f"Found {len(ips)} IP address(es) (possible C2 servers)")

        if info and info.get("extension") and self._is_suspicious_extension(info.get("extension")):
            score += 5
            reasons.append(f"Suspicious file extension: {info.get('extension')}")

        stats.update({
            "strings": len(strings),
            "urls": len(urls),
            "ips": len(ips),
            "commands": len(commands),
            "entropy": entropy,
        })

        # File type mismatch
        file_type = self.advanced.get("file_type", {})
        if file_type.get("magic_detected") and file_type.get("extension_match") is False:
            score += 15
            reasons.append(
                f"File extension mismatch! Bytes say '{file_type['magic_detected']}' "
                f"but extension is .{file_type.get('extension')} (common evasion technique)"
            )

        # ---- Pattern scanner findings ----
        pattern_matches = self.advanced.get("pattern_matches", [])
        severity_weights = {"critical": 30, "high": 20, "medium": 10}
        pattern_by_sev = {}
        for match in pattern_matches:
            sev = match.get("severity", "medium")
            pattern_by_sev.setdefault(sev, []).append(match)
            score += severity_weights.get(sev, 10)
            reasons.append(
                f"[{sev.upper()}] Pattern match: {match['rule']} ({match.get('type', 'unknown')}) - {match.get('description', '')}"
            )
        stats["pattern_matches"] = len(pattern_matches)

        # ---- PE Analysis ----
        pe = self.advanced.get("pe", {})
        if pe.get("is_valid"):
            pe_score = 0
            susp_apis = pe.get("suspicious_apis", [])
            if susp_apis:
                pe_score += min(len(susp_apis) * 2, 20)
                reasons.append(
                    f"PE file with {len(susp_apis)} suspicious API calls "
                    f"(e.g. {', '.join(a['api'] for a in susp_apis[:3])})"
                )
            for indicator in pe.get("packed", []):
                pe_score += 10
                reasons.append(f"PE packing detected: {indicator}")
            overlay = pe.get("overlay")
            if overlay:
                pe_score += 8
                reasons.append(f"PE overlay data found: {overlay.get('size_human')} appended to executable (common in droppers)")
            if pe.get("section_mismatch"):
                pe_score += 10
                reasons.extend(pe["section_mismatch"])
            cert = pe.get("security_flags", {})
            if cert and not cert.get("certificate_present") and self._is_exe_ext(info):
                pe_score += 5
                reasons.append("PE is signed-tampered or unsigned executable (considerable risk)")
            if pe_score:
                score += min(pe_score, 30)
                stats["pe_suspicious_apis"] = len(susp_apis)
                stats["pe_packed"] = len(pe.get("packed", []))

        # ---- ELF Analysis ----
        elf = self.advanced.get("elf", {})
        if elf.get("is_valid"):
            elf_score = 0
            elf_susp = elf.get("suspicious_functions", [])
            if elf_susp:
                elf_score += min(len(elf_susp) * 2, 20)
                reasons.append(
                    f"ELF file with {len(elf_susp)} suspicious functions "
                    f"(e.g. {', '.join(f['function'] for f in elf_susp[:3])})"
                )
            for sec in elf.get("suspicious_sections", []):
                elf_score += 10
                reasons.append(f"ELF suspicious section: {sec}")
            if elf_score:
                score += min(elf_score, 25)
                stats["elf_suspicious_functions"] = len(elf_susp)

        # ---- APK Analysis ----
        apk = self.advanced.get("apk", {})
        if apk.get("is_valid"):
            apk_score = 0
            dangerous = apk.get("dangerous_permissions", [])
            if dangerous:
                apk_score += min(len(dangerous) * 4, 20)
                reasons.append(
                    f"APK requests {len(dangerous)} dangerous permissions "
                    f"(e.g. {', '.join(d['permission'].split('.')[-1] for d in dangerous[:3])})"
                )
            for finding in apk.get("suspicious_code", []):
                apk_score += 8
                reasons.append(f"APK suspicious code in {finding.get('file')}: {finding.get('finding')}")
            if apk.get("manifest_plain"):
                apk_score += 8
                reasons.append("APK is debuggable (android:debuggable=true) - code tampering risk")
            if apk_score:
                score += min(apk_score, 30)
                stats["apk_dangerous_permissions"] = len(dangerous)
                stats["apk_suspicious_code"] = len(apk.get("suspicious_code", []))

        # Cap at 100
        score = min(score, 100)

        if score >= 70:
            level = "HIGH RISK"
            color = "red"
        elif score >= 40:
            level = "MEDIUM RISK"
            color = "orange"
        else:
            level = "LOW RISK"
            color = "green"

        return {
            "score": score,
            "level": level,
            "color": color,
            "reasons": reasons,
            "stats": stats,
        }

    @staticmethod
    def _is_suspicious_extension(ext):
        suspicious = {
            ".exe", ".dll", ".scr", ".bat", ".cmd", ".vbs", ".vbe",
            ".js", ".jse", ".wsf", ".wsh", ".ps1", ".psm1", ".hta",
            ".cpl", ".jar", ".apk", ".docm", ".xlsm", ".pptm",
        }
        return ext.lower() in suspicious

    @staticmethod
    def _is_exe_ext(info):
        return info.get("extension", "").lower() in (".exe", ".dll", ".scr", ".cpl")