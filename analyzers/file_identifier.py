import struct


class FileIdentifier:
    """Identify file type using magic bytes (signatures) instead of extensions."""

    SIGNATURES = [
        (b"MZ", "PE Executable (Windows)", "pe"),
        (b"\x7fELF", "ELF Executable (Linux/Unix)", "elf"),
        (b"PK\x03\x04", "ZIP Archive", "zip"),
        (b"PK\x05\x06", "ZIP Archive (empty)", "zip"),
        (b"PK\x07\x08", "ZIP Archive (spanned)", "zip"),
        (b"\x89PNG\r\n\x1a\n", "PNG Image", "png"),
        (b"\xff\xd8\xff", "JPEG Image", "jpeg"),
        (b"GIF8", "GIF Image", "gif"),
        (b"%PDF", "PDF Document", "pdf"),
        (b"{\\rtf", "RTF Document", "rtf"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE/Compound Document (doc/xls/ppt)", "ole"),
        (b"\x50\x4b\x03\x04\x14\x00\x06\x00", "Microsoft Office 2007+ (OOXML)", "ooxml"),
        (b"Rar!\x1a\x07", "RAR Archive", "rar"),
        (b"\x1f\x8b", "GZIP Archive", "gzip"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip Archive", "7z"),
        (b"\xfd7zXZ\x00", "XZ Archive", "xz"),
        (b"BZh", "BZip2 Archive", "bzip2"),
        (b"\xca\xfe\xba\xbe", "Java Class File", "class"),
        (b"\x50\x4b\x03\x04\x14\x00\x08\x08\x08\x00", "JAR/APK (ZIP-based)", "apk"),
        (b"java_serial", "Java Serialized Object", "java_serial"),
        (b"\x38\x35\xbe\xaf", "Dalvik Executable (DEX)", "dex"),
        (b"\xde\xa1\x5e\x40", "Dalvik Executable (DEX)", "dex"),
        (b"dex\n", "Dalvik Executable (DEX)", "dex"),
        (b"\xed\xab\xee\xdb", "Old Dalvik Executable", "dex"),
        (b"\x00asm", "WebAssembly Binary", "wasm"),
        (b"#!", "Script (shebang)", "script"),
        (b"\x7f\x45\x4c\x46\x02", "ELF 64-bit", "elf64"),
        (b"Macromedia", "Shockwave Flash (SWF)", "swf"),
        (b"CWS", "Shockwave Flash (SWF)", "swf"),
        (b"FWS", "Shockwave Flash (SWF)", "swf"),
        (b"ZWS", "Shockwave Flash (SWF)", "swf"),
        (b"SQLite format 3", "SQLite Database", "sqlite"),
        (b"\xff\xfe", "UTF-16 Text File", "text"),
        (b"\xfe\xff", "UTF-16 Text File", "text"),
        (b"\xef\xbb\xbf", "UTF-8 BOM Text File", "text"),
    ]

    SCRIPT_EXTENSIONS = {
        "py": "Python Script",
        "ps1": "PowerShell Script",
        "bat": "Batch File",
        "cmd": "Command Script",
        "vbs": "VBScript",
        "js": "JavaScript",
        "sh": "Shell Script",
        "pl": "Perl Script",
        "rb": "Ruby Script",
        "php": "PHP Script",
        "lua": "Lua Script",
        "hta": "HTML Application",
        "jar": "Java Archive",
        "wsf": "Windows Script File",
        "jse": "JScript Encoded",
        "vbe": "VBScript Encoded",
    }

    def __init__(self, data):
        self.data = data

    def detect(self, filename=None):
        """Return detected file type info."""
        result = {
            "magic_detected": None,
            "category": "unknown",
            "type_key": None,
            "extension_match": None,
        }

        # Check signatures
        for sig, name, key in self.SIGNATURES:
            if self.data[:len(sig)] == sig:
                result["magic_detected"] = name
                result["type_key"] = key
                break

        # If no match, check if starts with printable text
        if result["magic_detected"] is None:
            preview = self.data[:512]
            # Stop at first null byte (nulls often pad after text)
            nul_pos = preview.find(b"\x00")
            if nul_pos > 0:
                preview = preview[:nul_pos]
            if preview and all(32 <= b <= 126 or b in (9, 10, 13) for b in preview):
                result["magic_detected"] = "Plain Text"
                result["type_key"] = "text"

        # Check extension consistency if filename provided
        if filename:
            ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
            expected = self._expected_key(ext)
            result["extension"] = ext
            result["extension_title"] = self.SCRIPT_EXTENSIONS.get(ext, ext or "none")
            if expected and result["type_key"]:
                result["extension_match"] = (expected == result["type_key"])
            elif ext == "exe" and result["type_key"] == "pe":
                result["extension_match"] = True
            elif ext == "dll" and result["type_key"] == "pe":
                result["extension_match"] = True
            elif ext == "apk" and (result["type_key"] in ("apk", "zip", "ooxml")):
                result["extension_match"] = True
            elif ext and result["type_key"]:
                result["extension_match"] = False
            else:
                result["extension_match"] = None

        return result

    def _expected_key(self, ext):
        """Map common extensions to expected magic-type keys."""
        mapping = {
            "exe": "pe", "dll": "pe", "bin": "pe",
            "elf": "elf", "so": "elf",
            "apk": "apk", "dex": "dex",
            "jar": "apk", "zip": "zip",
            "pdf": "pdf", "docx": "ooxml", "xlsx": "ooxml",
            "pptx": "ooxml", "doc": "ole", "xls": "ole", "ppt": "ole",
            "rar": "rar", "7z": "7z", "gz": "gzip",
            "png": "png", "jpg": "jpeg", "gif": "gif",
            "txt": "text", "csv": "text", "log": "text",
            "sqlite": "sqlite", "db": "sqlite",
        }
        return mapping.get(ext)

    def is_executable(self):
        """Check if detected type is an executable/code type."""
        exec_types = {"pe", "elf", "script", "dex", "wasm", "class", "vbs", "js"}
        return self.type_key in exec_types

    @staticmethod
    def detect_from_path(file_path):
        """Convenience: detect file type from a path."""
        with open(file_path, "rb") as f:
            data = f.read(512)
        return FileIdentifier(data).detect()