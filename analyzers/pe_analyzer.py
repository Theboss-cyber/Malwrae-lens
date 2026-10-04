import math

import pefile


class PEAnalyzer:
    """Parse PE (Portable Executable) files to extract headers, sections,
    imports, and detect suspicious characteristics."""

    PE_MACHINE_TYPES = {
        0x014C: "x86 (32-bit)",
        0x8664: "x64 (64-bit)",
        0x01C0: "ARM",
        0xAA64: "ARM64",
        0x01F0: "PowerPC",
        0x0200: "Itanium",
    }

    CHARACTERISTICS = {
        0x0002: "EXECUTABLE_IMAGE",
        0x0020: "LARGE_ADDRESS_AWARE",
        0x0100: "32BIT_MACHINE",
        0x0200: "DEBUG_STRIPPED",
        0x2000: "DLL",
    }

    DllCharacteristics = {
        0x0020: "HIGH_ENTROPY_VA",
        0x0040: "DYNAMIC_BASE (ASLR)",
        0x0080: "FORCE_INTEGRITY",
        0x0100: "NX_COMPAT (DEP)",
        0x0400: "NO_ISOLATION",
        0x0800: "NO_SEH",
        0x1000: "NO_BIND",
        0x4000: "WDM_DRIVER",
        0x8000: "TERMINAL_SERVER_AWARE",
    }

    SUSPICIOUS_DLLS = [
        "wininet.dll", "ws2_32.dll", "winhttp.dll", "urlmon.dll",
        "advapi32.dll", "ntdll.dll", "psapi.dll", "user32.dll",
    ]

    SUSPICIOUS_APIS = {
        "VirtualAlloc": "Memory allocation (often used for shellcode injection)",
        "VirtualAllocEx": "Remote memory allocation (process injection)",
        "WriteProcessMemory": "Writes to another process's memory (code injection)",
        "CreateRemoteThread": "Creates thread in another process (process injection)",
        "NtMapViewOfSection": "Maps view of section (process injection)",
        "NtUnmapViewOfSection": "Unmaps memory in remote process (process hollowing)",
        "ReadProcessMemory": "Reads another process's memory",
        "SetWindowsHookEx": "Installs keyboard/mouse hooks (keylogging)",
        "GetAsyncKeyState": "Keyboard state polling (keylogging)",
        "GetKeyState": "Keyboard state (keylogging)",
        "RegSetValueEx": "Modifies registry values (persistence)",
        "RegCreateKeyEx": "Creates registry keys (persistence)",
        "ShellExecuteEx": "Executes another program (payload execution)",
        "WinExec": "Executes command (payload execution)",
        "CreateProcess": "Creates new process (payload execution)",
        "CreateProcessInternalW": "Internal process creation",
        "Process32First": "Process enumeration (evasion/recon)",
        "Process32Next": "Process enumeration (evasion/recon)",
        "CreateToolhelp32Snapshot": "Process enumeration (evasion/recon)",
        "GetComputerName": "System information gathering",
        "GetVolumeInformation": "System/environment fingerprinting",
        "GetSystemTime": "Time-based checks",
        "SetTimer": "Timer-based anti-analysis",
        "CryptEncrypt": "Encryption routines (ransomware/data theft)",
        "CryptDecrypt": "Decryption routines",
        "IsDebuggerPresent": "Anti-debugging detection",
        "CheckRemoteDebuggerPresent": "Anti-debugging detection",
        "NtGlobalFlag": "Anti-debugging detection",
        "GetModuleHandle": "Dynamic resolution (obfuscation)",
        "LoadLibrary": "Dynamic library loading (obfuscation)",
        "GetProcAddress": "Dynamic API resolution (obfuscation)",
        "InternetOpen": "Network communication (C2)",
        "InternetConnect": "Network communication (C2)",
        "HttpSendRequest": "Network communication (C2)",
        "URLDownloadToFile": "Downloads payload from internet",
        "WSAStartup": "Network initialization (C2)",
        "connect": "Network connection (C2)",
        "send": "Network data exfiltration",
        "recv": "Receives command data",
        "sleep": "Sleep-based evasion",
    }

    def __init__(self, file_path):
        self.file_path = file_path
        self.results = {}

    def analyze(self):
        """Run all PE analysis and return structured results."""
        try:
            self.pe = pefile.PE(self.file_path, fast_load=False)
        except Exception as e:
            return {"error": f"Failed to parse PE: {str(e)}"}

        results = {
            "is_valid": True,
            "machine": self._get_machine(),
            "characteristics": self._get_characteristics(),
            "dll_characteristics": self._get_dll_characteristics(),
            "sections": self._get_sections(),
            "imports": self._get_imports(),
            "suspicious_apis": self._get_suspicious_apis(),
            "entry_point": self._get_entry_point(),
            "timestamp": self._get_timestamp(),
            "packed": self._is_packed(),
            "overlay": self._get_overlay(),
            "security_flags": self._get_security_info(),
            "section_mismatch": self._check_section_mismatch(),
        }

        self.results = results
        return results

    def _get_machine(self):
        try:
            machine = self.pe.FILE_HEADER.Machine
            return self.PE_MACHINE_TYPES.get(machine, f"Unknown (0x{machine:04X})")
        except Exception:
            return "Unknown"

    def _get_characteristics(self):
        flags = []
        try:
            value = self.pe.FILE_HEADER.Characteristics
            for bit, name in self.CHARACTERISTICS.items():
                if value & bit:
                    flags.append(name)
        except Exception:
            pass
        return flags

    def _get_dll_characteristics(self):
        flags = []
        try:
            value = self.pe.OPTIONAL_HEADER.DllCharacteristics
            for bit, name in self.DllCharacteristics.items():
                if value & bit:
                    flags.append(name)
        except Exception:
            pass
        return flags

    def _get_sections(self):
        sections = []
        try:
            for section in self.pe.sections:
                name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                data = section.get_data()
                entropy = self._calculate_entropy(data) if data else 0.0
                sections.append({
                    "name": name,
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "entropy": round(entropy, 2),
                    "characteristics": hex(section.Characteristics),
                    "executable": bool(section.Characteristics & 0x20000000),
                    "writable": bool(section.Characteristics & 0x80000000),
                })
        except Exception:
            pass
        return sections

    def _get_imports(self):
        imports = []
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace")
                functions = []
                for imp in entry.imports:
                    if imp.name:
                        functions.append(imp.name.decode("utf-8", errors="replace"))
                    else:
                        functions.append(f"ordinal_{imp.ordinal}")
                imports.append({"dll": dll, "functions": functions})
        except Exception:
            pass
        return imports

    def _get_suspicious_apis(self):
        suspicious = []
        try:
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace").lower()
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode("utf-8", errors="replace")
                        if name in self.SUSPICIOUS_APIS:
                            suspicious.append({
                                "api": name,
                                "dll": dll,
                                "reason": self.SUSPICIOUS_APIS[name],
                            })
        except Exception:
            pass
        return suspicious

    def _get_entry_point(self):
        try:
            ep = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            image_base = self.pe.OPTIONAL_HEADER.ImageBase
            return {
                "raw": hex(ep),
                "image_base": hex(image_base),
                "virtual": hex(image_base + ep),
            }
        except Exception:
            return None

    def _get_timestamp(self):
        from datetime import datetime, timezone

        try:
            ts = self.pe.FILE_HEADER.TimeDateStamp
            return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        except Exception:
            return "Unknown"

    def _is_packed(self):
        """Detect packing by section entropy and naming."""
        indicators = []
        try:
            for section in self.pe.sections:
                name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace").lower()
                data = section.get_data()
                entropy = self._calculate_entropy(data) if data else 0.0
                if name in (".upx", ".pack", ".themida", ".vmp", ".aspack") or "pack" in name:
                    indicators.append(f"Known packer section: {name}")
                if entropy > 7.0 and name not in (".data", ".rsrc"):
                    indicators.append(f"High entropy section {name}: {entropy:.2f} (possible packing)")
        except Exception:
            pass
        return indicators

    def _get_overlay(self):
        """Detect extra data appended to PE (common in malware droppers)."""
        try:
            overlay = self.pe.get_overlay_data_start_offset()
            total = self.pe.full_size()
            if overlay and overlay < total:
                size = total - overlay
                return {
                    "offset": hex(overlay),
                    "size": size,
                    "size_human": self._human_size(size),
                }
        except Exception:
            pass
        return None

    def _get_security_info(self):
        try:
            sec_dir = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
            return {
                "certificate_present": sec_dir.VirtualAddress != 0,
                "certificate_size": sec_dir.Size,
            }
        except Exception:
            return {"certificate_present": False, "certificate_size": 0}

    def _check_section_mismatch(self):
        """Detect malicious section characteristics (write+exec)."""
        issues = []
        try:
            for section in self.pe.sections:
                name = section.Name.rstrip(b"\x00").decode("utf-8", errors="replace")
                exec_bit = section.Characteristics & 0x20000000
                write_bit = section.Characteristics & 0x80000000
                if exec_bit and write_bit:
                    issues.append(f"Section '{name}' is both writable and executable")
        except Exception:
            pass
        return issues

    @staticmethod
    def _calculate_entropy(data):
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    @staticmethod
    def _human_size(num):
        for unit in ["B", "KB", "MB", "GB"]:
            if num < 1024.0:
                return f"{num:.2f} {unit}"
            num /= 1024.0
        return f"{num:.2f} TB"

    @staticmethod
    def _is_pe(data):
        """Static check if file is a PE (MZ header)."""
        return len(data) > 0 and data[:2] == b"MZ"