import math
import struct


class ELFAnalyzer:
    """Parse ELF (Executable and Linkable Format) files manually.
    No external dependencies required."""

    ELF_MACHINES = {
        0x00: "No specific instruction set",
        0x03: "Intel x86",
        0x08: "MIPS",
        0x14: "PowerPC",
        0x28: "ARM",
        0x3E: "AMD x86-64",
        0xB7: "AArch64",
        0xF3: "RISC-V",
    }

    ELF_TYPES = {
        0x00: "NONE",
        0x01: "REL (Relocatable)",
        0x02: "EXEC (Executable)",
        0x03: "DYN (Shared object)",
        0x04: "CORE",
    }

    ELF_ABI = {
        0x00: "System V",
        0x03: "Linux",
        0x06: "Solaris",
    }

    SECTION_NAMES = [
        "\x00", ".text", ".data", ".bss", ".rodata", ".init", ".fini",
        ".plt", ".got", ".got.plt", ".dynsym", ".dynstr", ".symtab",
        ".strtab", ".rela", ".rel", ".dynamic", ".interp", ".comment",
        ".shstrtab",
    ]

    SUSPICIOUS_FUNCTIONS = {
        "system": "Executes shell commands",
        "execve": "Executes new program",
        "execvp": "Executes new program",
        "execl": "Executes new program",
        "popen": "Executes commands with pipe",
        "fork": "Process creation",
        "ptrace": "Debugging/anti-analysis",
        "strcpy": "Buffer overflow potential",
        "sprintf": "Format string/buffer overflow potential",
        "vsprintf": "Format string/buffer overflow potential",
        "gets": "Unsafe input (buffer overflow)",
        "strcat": "Buffer overflow potential",
        "mprotect": "Changes memory permissions (shellcode)",
        "mmap": "Memory mapping (shellcode)",
        "socket": "Network communication (C2)",
        "connect": "Network connection (C2)",
        "bind": "Network listener",
        "recv": "Network data receipt",
        "send": "Network data exfiltration",
        "gethostbyname": "DNS resolution (C2)",
        "dlopen": "Dynamic library loading",
        "dlsym": "Dynamic symbol resolution",
        "setuid": "Privilege escalation",
        "setresuid": "Privilege escalation",
        "setgid": "Privilege escalation",
    }

    def __init__(self, file_path):
        self.file_path = file_path
        with open(file_path, "rb") as f:
            self.data = f.read()

    def analyze(self):
        """Parse ELF header, sections, and check security properties."""
        if len(self.data) < 52:
            return {"error": "File too small to be a valid ELF"}

        # Determine 32 vs 64-bit
        self.is_64 = self.data[4] == 2
        header_size = 64 if self.is_64 else 52

        try:
            if self.is_64:
                header = struct.unpack_from("<16sHHIQQQIHHHHHH", self.data, 0)
            else:
                header = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data, 0)
        except struct.error:
            return {"error": "Failed to parse ELF header"}

        e_ident = self.data[0:16]
        elf_class = "64-bit" if self.is_64 else "32-bit"
        elf_data = "Little-endian" if e_ident[5] == 1 else "Big-endian"
        elf_version = e_ident[6]
        elf_osabi = self.ELF_ABI.get(e_ident[7], f"Unknown ({e_ident[7]})")
        elf_abiver = e_ident[8]

        e_type = self.ELF_TYPES.get(header[1], f"Unknown ({header[1]})")
        e_machine = self.ELF_MACHINES.get(header[2], f"Unknown (0x{header[2]:x})")
        e_version = header[3]

        if self.is_64:
            e_entry = header[4]
            e_phoff = header[5]
            e_shoff = header[6]
            e_flags = header[7]
            e_ehsize = header[8]
            e_phentsize = header[9]
            e_phnum = header[10]
            e_shentsize = header[11]
            e_shnum = header[12]
            e_shstrndx = header[13]
        else:
            e_entry = header[4]
            e_phoff = header[5]
            e_shoff = header[6]
            e_flags = header[7]
            e_ehsize = header[8]
            e_phentsize = header[9]
            e_phnum = header[10]
            e_shentsize = header[11]
            e_shnum = header[12]
            e_shstrndx = header[13]

        sections = self._parse_sections(e_shoff, e_shentsize, e_shnum, e_shstrndx)
        dynamic_symbols = self._parse_dynamic_symbols(e_shoff, e_shentsize, e_shnum, sections)
        suspicious = self._find_suspicious_functions(dynamic_symbols)
        entropy = self._calculate_entropy()

        security = {
            "is_pie": e_type in ("DYN (Shared object)", "REL (Relocatable)"),
            "has_interpreter": any(s["name"] == ".interp" for s in sections),
            "stack_exec": self._has_stack_exec(sections),
        }

        suspicious_sections = []
        for s in sections:
            if s["executable"] and s["entropy"] > 7.0 and s["name"] not in (".text", ".plt"):
                suspicious_sections.append(
                    f"Executable section '{s['name']}' with high entropy ({s['entropy']:.1f})"
                )

        return {
            "is_valid": True,
            "elf_class": elf_class,
            "endianness": elf_data,
            "version": elf_version,
            "osabi": elf_osabi,
            "abi_version": elf_abiver,
            "type": e_type,
            "machine": e_machine,
            "entry_point": hex(e_entry),
            "flags": e_flags,
            "header_size": e_ehsize,
            "sections": sections,
            "dynamic_symbols": dynamic_symbols[:100],
            "suspicious_functions": suspicious,
            "entropy": round(entropy, 2),
            "security": security,
            "suspicious_sections": suspicious_sections,
        }

    def _parse_sections(self, e_shoff, e_shentsize, e_shnum, e_shstrndx):
        """Parse section headers."""
        sections = []
        if e_shnum == 0 or e_shoff == 0:
            return sections

        try:
            string_table_offset = None
            if e_shstrndx < e_shnum:
                if self.is_64:
                    sh_entry = struct.unpack_from(
                        "<IIQQQQIIQQ", self.data, e_shoff + e_shstrndx * e_shentsize
                    )
                else:
                    sh_entry = struct.unpack_from(
                        "<IIIIIIIIII", self.data, e_shoff + e_shstrndx * e_shentsize
                    )
                string_table_offset = sh_entry[4]

            for i in range(e_shnum):
                off = e_shoff + i * e_shentsize
                if len(self.data) < off + e_shentsize:
                    continue
                if self.is_64:
                    sh = struct.unpack_from("<IIQQQQIIQQ", self.data, off)
                else:
                    sh = struct.unpack_from("<IIIIIIIIII", self.data, off)

                sh_name = sh[0]
                sh_type = sh[1]
                sh_offset = sh[4]
                sh_size = sh[5]
                sh_flags = sh[6]

                name = self._get_section_name(string_table_offset, sh_name)

                entropy = 0.0
                if sh_size > 0 and sh_offset + sh_size <= len(self.data):
                    section_data = self.data[sh_offset:sh_offset + sh_size]
                    entropy = self._calc_entropy(section_data)

                sections.append({
                    "index": i,
                    "name": name,
                    "type": sh_type,
                    "offset": sh_offset,
                    "size": sh_size,
                    "entropy": round(entropy, 2),
                    "executable": bool(sh_flags & 0x4),
                    "writable": bool(sh_flags & 0x1),
                    "allocated": bool(sh_flags & 0x2),
                })
        except (struct.error, IndexError):
            pass
        return sections

    def _get_section_name(self, string_table_offset, name_offset):
        if string_table_offset is None or name_offset == 0:
            return f"section_{name_offset}"
        end = self.data.find(b"\x00", string_table_offset + name_offset)
        if end == -1:
            return f"section_{name_offset}"
        try:
            return self.data[string_table_offset + name_offset:end].decode("utf-8", errors="replace")
        except Exception:
            return f"section_{name_offset}"

    def _parse_dynamic_symbols(self, e_shoff, e_shentsize, e_shnum, sections):
        """Extract function names from dynamic symbol table."""
        symbols = []
        symtab = next((s for s in sections if s["name"] in (".dynsym", ".symtab")), None)
        strtab = next((s for s in sections if s["name"] == ".dynstr"), None)
        if not strtab:
            strtab = next((s for s in sections if s["name"] == ".strtab"), None)

        if not symtab or not strtab:
            return symbols

        try:
            entry_size = 24 if self.is_64 else 16
            str_data = self.data[strtab["offset"]:strtab["offset"] + strtab["size"]]
            str_off = 0
            for i in range(symtab["size"] // entry_size):
                off = symtab["offset"] + i * entry_size
                if self.is_64:
                    sym = struct.unpack_from("<IBBHQQ", self.data, off)
                    str_index = sym[0]
                else:
                    sym = struct.unpack_from("<IIIBBH", self.data, off)
                    str_index = sym[0]
                name = None
                if str_index < len(str_data):
                    end = str_data.find(b"\x00", str_index)
                    if end != -1:
                        name = str_data[str_index:end].decode("utf-8", errors="replace")
                if name and len(name) > 0:
                    symbols.append(name)
        except (struct.error, IndexError):
            pass
        return symbols

    def _find_suspicious_functions(self, symbols):
        suspicious = []
        for sym in set(symbols):
            if sym in self.SUSPICIOUS_FUNCTIONS:
                suspicious.append({
                    "function": sym,
                    "reason": self.SUSPICIOUS_FUNCTIONS[sym],
                })
        return suspicious

    def _has_stack_exec(self, sections):
        # If no GNU_STACK section marker, assume a non-exec stack (modern default)
        stack = [s for s in sections if s["name"] == ".note.GNU-stack"]
        if stack:
            return stack[0]["executable"]
        return False

    @staticmethod
    def _calc_entropy(data):
        if not data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy

    def _calculate_entropy(self):
        if not self.data:
            return 0.0
        entropy = 0.0
        for x in range(256):
            p_x = self.data.count(x) / len(self.data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        return entropy