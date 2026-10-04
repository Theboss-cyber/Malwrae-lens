import re


class PatternScanner:
    """Lightweight pattern-matching scanner (YARA-style without the C library).
    Detects known malware families, packers, and suspicious indicators."""

    RULES = [
        {
            "name": "Metasploit Meterpreter",
            "description": "Metasploit payload indicators",
            "pattern": rb"(meterpreter|metasploit|msfconsole)",
            "severity": "high",
            "type": "exploit",
        },
        {
            "name": "Cobalt Strike Beacon",
            "description": "Cobalt Strike C2 beacon signatures",
            "pattern": rb"(beacon|COBALT_STRIKE|cobaltstrike|127\.0\.0\.1:.*beacon)",
            "severity": "high",
            "type": "c2",
        },
        {
            "name": "Mimikatz",
            "description": "Credential dumping tool",
            "pattern": rb"(mimikatz|sekurlsa|kerberos::golden)",
            "severity": "high",
            "type": "credential_theft",
        },
        {
            "name": "AutoIt Compiler",
            "description": "AutoIt-packed malware common in banking trojans",
            "pattern": rb"(\x00AUTOIT|AutoIt_RLS|!AUT!)\x00",
            "severity": "high",
            "type": "packer",
        },
        {
            "name": "UPX Packer",
            "description": "UPX compressed executable",
            "pattern": rb"upx[0-9!]",
            "severity": "medium",
            "type": "packer",
        },
        {
            "name": "PowerShell Encoded",
            "description": "Encoded PowerShell (common in LOLBin attacks)",
            "pattern": rb"powershell.*-enc|powershell.*-encodedcommand|FromBase64String",
            "severity": "high",
            "type": "obfuscation",
        },
        {
            "name": "Base64 Obfuscation",
            "description": "Base64-encoded content",
            "pattern": rb"(FromBase64|Convert\.FromBase64|base64_decode)",
            "severity": "medium",
            "type": "obfuscation",
        },
        {
            "name": "Registry Persistence",
            "description": "Registry auto-start registry keys",
            "pattern": rb"(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|CurrentVersion\\\\Run)",
            "severity": "high",
            "type": "persistence",
        },
        {
            "name": "Scheduled Task Persistence",
            "description": "Scheduled task creation for persistence",
            "pattern": rb"(schtasks /create|schtasks\.exe|TaskScheduler)",
            "severity": "high",
            "type": "persistence",
        },
        {
            "name": "Polymorphic Shellcode",
            "description": "Common shellcode byte patterns",
            "pattern": rb"(\x31\xc0\x50\x68\x2f\x2f\x73\x68|\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68|\x31\xd2\x52\x68\x2f\x2f\x73\x68)",
            "severity": "critical",
            "type": "shellcode",
        },
        {
            "name": "PowerShell Web Download",
            "description": "Download and execute pattern (LOLBin)",
            "pattern": rb"(IEX\s*\(\s*New-Object|Invoke-WebRequest|Net\.WebClient|WebClient\.DownloadString)", 
            "severity": "high",
            "type": "lolbin",
        },
        {
            "name": "WMI Persistence",
            "description": "WMI event subscription persistence",
            "pattern": rb"(__EventFilter|CommandLineEventConsumer|ActiveScriptEventConsumer)",
            "severity": "high",
            "type": "persistence",
        },
        {
            "name": "Anti-Analysis",
            "description": "Anti-debug/anti-VM indicators",
            "pattern": rb"(IsDebuggerPresent|CheckRemoteDebuggerPresent|vmware|vbox|sunbelt|wine_gdi)",
            "severity": "medium",
            "type": "evasion",
        },
        {
            "name": "Keylogger",
            "description": "Keyboard hooking indicators",
            "pattern": rb"(SetWindowsHookEx|GetAsyncKeyState|WH_KEYBOARD|keybd_event)",
            "severity": "high",
            "type": "spyware",
        },
        {
            "name": "Ransomware Indicators",
            "description": "File extension changing / encryption patterns",
            "pattern": rb"(\.locked|\.encrypted|\.crypt|\.paywall|Your files have been encrypted|read_me\.txt)",
            "severity": "high",
            "type": "ransomware",
        },
        {
            "name": "Banking Trojan",
            "description": "Known banking trojan family indicators",
            "pattern": rb"(zbot|zeus|ramnit|spyeye|dridex|jabberlox)",
            "severity": "high",
            "type": "banking",
        },
        {
            "name": "Cryptominer",
            "description": "Mining pool addresses",
            "pattern": rb"(pool\.minergate|xmr\.pool|stratum\+tcp|antpool|nanopool)",
            "severity": "medium",
            "type": "miner",
        },
        {
            "name": "RAT (Remote Access)",
            "description": "Remote admin tool indicators",
            "pattern": rb"(njRAT|DarkComet|X-Agent|Gh0st|rat\.exe|RemoteAdmin)",
            "severity": "high",
            "type": "rat",
        },
        {
            "name": "Credential Theft",
            "description": "Password/cookie dumping indicators",
            "pattern": rb"(\.txt\s*wget|unprotect|DPAPI|lsass|SAM\.dll|passwords\.txt|cookies\.db)",
            "severity": "high",
            "type": "credential_theft",
        },
        {
            "name": "Hidden Process",
            "description": "Process hiding / unrelated indicators",
            "pattern": rb"(ProcessIdleTasks|CreateRemoteThread|NtSetInformationProcess)",
            "severity": "medium",
            "type": "evasion",
        },
    ]

    def __init__(self, data=None, file_path=None):
        self.data = data
        self.file_path = file_path

    def scan(self):
        """Scan data against all rules."""
        if self.data is None and self.file_path:
            with open(self.file_path, "rb") as f:
                self.data = f.read()

        matches = []
        if not self.data:
            return matches

        # Case-insensitive scan
        lower_data = self.data.lower()

        for rule in self.RULES:
            pattern = rule["pattern"]
            try:
                if re.search(pattern, lower_data):
                    matches.append({
                        "rule": rule["name"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "type": rule["type"],
                    })
            except re.error:
                continue

        return matches

    @staticmethod
    def scan_file(file_path):
        """Convenience: scan a file path."""
        scanner = PatternScanner(file_path=file_path)
        return scanner.scan()

    @staticmethod
    def scan_memory_data(data):
        """Convenience: scan in-memory bytes."""
        scanner = PatternScanner(data=data)
        return scanner.scan()