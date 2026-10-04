"""Generate standalone HTML reports and JSON exports of analysis results."""

import json
import re
from datetime import datetime


def _fmt_size(num):
    if num is None:
        return "N/A"
    for unit in ["B", "KB", "MB", "GB"]:
        if num < 1024.0:
            return f"{num:.2f} {unit}"
        num /= 1024.0
    return f"{num:.2f} TB"


def _severity_color(sev):
    return {
        "critical": "#9d0208",
        "high": "#e74c3c",
        "red": "#e74c3c",
        "medium": "#e67e22",
        "orange": "#e67e22",
        "low": "#25a244",
        "green": "#25a244",
        "info": "#3498db",
    }.get(sev, "#8a8a8a")


def _build_body(results):
    """Return the HTML body content shared by the report and the web page."""
    risk = results.get("risk", {})
    info = results.get("info", {})
    hashes = results.get("hashes", {})
    file_type = results.get("file_type", {})
    pe = results.get("pe")
    elf = results.get("elf")
    apk = results.get("apk")
    vt = results.get("virustotal")
    pattern_matches = results.get("pattern_matches", [])

    sections = []

    # Header
    sections.append(f"""
    <div class="report-header">
        <h1>🛡️ MalwareLens Analysis Report</h1>
        <p class="sub">File: <strong>{html_escape(info.get('filename', 'N/A'))}</strong> ·
           Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    """)

    # Executive summary
    vt_summary = ""
    vt_vendors = ""
    if vt and vt.get("enabled"):
        f = vt.get("file")
        if f:
            if f.get("found"):
                vt_summary = f"""
                <div class="vt-box">
                    <span class="vt-badge {'vt-clean' if f['detections'] == 0 else 'vt-mal' if f['detections'] >= 3 else 'vt-susp'}">
                        {f['detections']}/{f['total_engines']} detections on VirusTotal
                    </span>
                </div>"""
                vendors = f.get("malicious_vendors") or []
                if vendors:
                    rows = "".join(
                        f"<tr><th>{html_escape(v['engine'])}</th>"
                        f"<td><span style='color:#e74c3c;font-weight:600'>{html_escape(v.get('result') or v.get('category') or '')}</span></td></tr>"
                        for v in vendors
                    )
                    vt_vendors = f"""
                    <h2>☣️ VirusTotal Detections ({len(vendors)} vendors)</h2>
                    <table class="kv">{rows}</table>
                    """
            else:
                vt_summary = f"""
                <div class="vt-box"><span class="vt-badge vt-unknown">
                    VirusTotal: {f.get('error', 'no result')}
                </span></div>"""
        else:
            vt_summary = '<div class="vt-box"><span class="vt-badge vt-unknown">VirusTotal integration not configured</span></div>'

    sections.append(f"""
    <div class="exec-summary">
        <div class="score-box" style="--lc:{_severity_color(risk.get('color'))}">
            <div class="score-num">{risk.get('score', 0)}</div>
            <div class="score-label">/100 Risk Score</div>
        </div>
        <div class="exec-text">
            <div class="risk-level" style="color:{_severity_color(risk.get('color'))}">{risk.get('level', 'UNKNOWN')}</div>
            {vt_summary}
            <p>{_overall_summary(results)}</p>
        </div>
    </div>
    """)

    # Findings
    if risk.get("reasons"):
        items = "".join(f"<li>{html_escape(r)}</li>" for r in risk["reasons"])
        sections.append(f"""
        <h2>📌 Findings</h2>
        <ul class="findings">{items}</ul>
        """)

    # VirusTotal vendor detections
    if vt_vendors:
        sections.append(vt_vendors)

    # File information
    info_items = [
        ("Filename", info.get("filename", "N/A")),
        ("Size", f"{info.get('size_human', '?')} ({_fmt_size(info.get('size_bytes'))})"),
        ("Extension", info.get("extension", "N/A")),
        ("Last Modified", info.get("last_modified", "N/A")),
    ]
    if file_type.get("magic_detected"):
        match_note = ""
        if file_type.get("extension_match") is False:
            match_note = ' <span style="color:#e74c3c">⚠ EXTENSION MISMATCH</span>'
        elif file_type.get("extension_match"):
            match_note = ' <span style="color:#25a244">✓</span>'
        info_items.append(("Detected Type", f"{file_type['magic_detected']}{match_note}"))
    rows = "".join(
        f"<tr><th>{html_escape(k)}</th><td>{html_escape(v)}</td></tr>"
        for k, v in info_items if v not in (None, "")
    )
    sections.append(f"""
    <h2>📄 File Information</h2>
    <table class="kv">{rows}</table>
    """)

    # Hashes
    hash_rows = "".join(
        f"<tr><th>{k.upper()}</th><td class='mono'>{html_escape(hash_value)}</td></tr>"
        for k, hash_value in hashes.items()
    ) if hashes else ""
    if hash_rows:
        sections.append(f"""
        <h2>🔑 Cryptographic Hashes</h2>
        <table class="kv mono-table">{hash_rows}</table>
        """)

    # PE
    if pe and pe.get("is_valid"):
        rows = "".join(
            f"<tr><th>{html_escape(k)}</th><td>{html_escape(str(v))}</td></tr>"
            for k, v in [
                ("Machine", pe.get("machine")),
                ("Entry Point", (pe.get("entry_point") or {}).get("virtual")),
                ("Compile Time", pe.get("timestamp")),
                ("Overlay", ((pe.get("overlay") or {}).get("size_human") + " appended at " + str((pe.get("overlay") or {}).get("offset")))
                    if pe.get("overlay") else "None"),
            ]
        )
        sections.append(f"""
        <h2>🪟 PE Analysis</h2>
        <table class="kv">{rows}</table>
        """)
        if pe.get("suspicious_apis"):
            items = "".join(
                f"<li><code>{html_escape(a['api'])}</code> in {html_escape(a['dll'])} — {html_escape(a['reason'])}</li>"
                for a in pe["suspicious_apis"][:20]
            )
            sections.append(f"<h3>Suspicious API Calls ({len(pe['suspicious_apis'])})</h3><ul class='findings'>{items}</ul>")
        if pe.get("packed"):
            items = "".join(f"<li>{html_escape(p)}</li>" for p in pe["packed"])
            sections.append(f"<h3>Packing Indicators</h3><ul class='findings'>{items}</ul>")

    # ELF
    if elf and elf.get("is_valid"):
        rows = "".join(
            f"<tr><th>{html_escape(k)}</th><td>{html_escape(str(v))}</td></tr>"
            for k, v in [
                ("Class", elf.get("elf_class")),
                ("Type", elf.get("type")),
                ("Machine", elf.get("machine")),
                ("Entry Point", elf.get("entry_point")),
            ]
        )
        sections.append(f"""
        <h2>🐧 ELF Analysis</h2>
        <table class="kv">{rows}</table>
        """)
        if elf.get("suspicious_functions"):
            items = "".join(
                f"<li><code>{html_escape(f['function'])}</code> — {html_escape(f['reason'])}</li>"
                for f in elf["suspicious_functions"][:20]
            )
            sections.append(f"<h3>Suspicious Functions</h3><ul class='findings'>{items}</ul>")

    # APK
    if apk and apk.get("is_valid"):
        rows = "".join(
            f"<tr><th>{html_escape(k)}</th><td>{html_escape(str(v))}</td></tr>"
            for k, v in [
                ("Package", apk.get("package_name")),
                ("Permissions", f"{apk.get('permission_count', 0)} declared"),
                ("Obfuscated/Debuggable", "Yes" if apk.get("manifest_plain") else "No"),
                ("Total Entries", apk.get("total_entries")),
            ]
        )
        sections.append(f"""
        <h2>🤖 APK Analysis</h2>
        <table class="kv">{rows}</table>
        """)
        if apk.get("dangerous_permissions"):
            items = "".join(
                f"<li><code>{html_escape(p['permission'])}</code> — {html_escape(p['reason'])}</li>"
                for p in apk["dangerous_permissions"][:20]
            )
            sections.append(f"<h3>Dangerous Permissions</h3><ul class='findings'>{items}</ul>")

    # Pattern matches
    if pattern_matches:
        items = "".join(
            f"<li><span class='sev' style='background:{_severity_color(m.get('severity'))}'>"
            f"{html_escape(m.get('severity',''))}</span> "
            f"<strong>{html_escape(m['rule'])}</strong> — {html_escape(m.get('description',''))}</li>"
            for m in pattern_matches
        )
        sections.append(f"""
        <h2>🎯 Signature Matches</h2>
        <ul class="findings">{items}</ul>
        """)

    # Indicators
    if results.get("urls"):
        items = "".join(f"<li><code>{html_escape(u)}</code></li>" for u in results["urls"][:30])
        sections.append(f"<h2>🌐 URLs</h2><ul class='findings'>{items}</ul>")
    if results.get("ips"):
        items = "".join(f"<li><code>{html_escape(i)}</code></li>" for i in results["ips"][:30])
        sections.append(f"<h2>🌍 IP Addresses</h2><ul class='findings'>{items}</ul>")
    if results.get("commands"):
        items = "".join(f"<li><code>{html_escape(c)}</code></li>" for c in results["commands"])
        sections.append(f"<h2>⚡ Suspicious Commands</h2><ul class='findings'>{items}</ul>")

    sections.append("""
    <div class="footer-note">
        Report generated by <strong>MalwareLens</strong> — static analysis only.
        Files are never executed during analysis.
    </div>
    """)

    return "\n".join(sections)


def _overall_summary(results):
    """One-sentence human summary of the analysis."""
    risk = results.get("risk", {})
    score = risk.get("score", 0)
    level = risk.get("level", "UNKNOWN")
    reasons = risk.get("reasons", [])
    file_type = results.get("file_type", {}).get("magic_detected") or "unknown type"
    filename = results.get("info", {}).get("filename", "the sample")

    if score >= 70:
        wording = "is considered HIGHLY SUSPICIOUS and should be handled with extreme caution."
    elif score >= 40:
        wording = "shows MEDIUM risk indicators and warrants further investigation."
    else:
        wording = "shows LOW risk indicators based on static analysis."
    return f"<b>{html_escape(filename)}</b> ({html_escape(file_type)}, score {score}/100 – {html_escape(level)}): {wording}"


def generate_html_report(results):
    """Generate a fully self-contained HTML report (inline CSS, no external files)."""
    body = _build_body(results)
    risk = results.get("risk", {})

    css = """
    body { font-family: -apple-system, 'Segoe UI', Roboto, sans-serif; margin: 0; background: #f5f6fa; color: #2c3e50; line-height: 1.6; }
    .page { max-width: 900px; margin: 0 auto; padding: 30px 20px 60px; }
    .report-header { border-bottom: 3px solid #0f3460; padding-bottom: 15px; margin-bottom: 25px; }
    .report-header h1 { margin: 0 0 4px; color: #0f3460; }
    .report-header .sub { color: #7f8c8d; margin: 0; font-size: 0.9em; }
    h2 { color: #0f3460; border-bottom: 1px solid #dcdde1; padding-bottom: 6px; margin-top: 30px; font-size: 1.2em; }
    h3 { color: #e94560; margin: 18px 0 8px; font-size: 1em; }
    .exec-summary { display: flex; gap: 25px; align-items: center; background: #fff; border: 1px solid #dcdde1; border-radius: 10px; padding: 20px; flex-wrap: wrap; }
    .score-box { width: 100px; height: 100px; border-radius: 50%; background: conic-gradient(var(--lc) 0 calc(var(--p)*1%), #ecf0f1 0); display: flex; flex-direction: column; align-items: center; justify-content: center; position: relative; }
    .score-box::before { content:''; position:absolute; inset:12px; border-radius:50%; background:#fff; }
    .score-num { position: relative; z-index: 1; font-size: 1.8em; font-weight: 800; color: var(--lc); }
    .score-label { position: relative; z-index: 1; font-size: 0.6em; color: #7f8c8d; }
    .risk-level { font-size: 1.5em; font-weight: 800; }
    .exec-text { flex: 1; }
    .exec-text p { margin: 8px 0 0; color: #34495e; }
    table.kv { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #dcdde1; border-radius: 8px; overflow: hidden; }
    table.kv th, table.kv td { padding: 8px 14px; text-align: left; border-bottom: 1px solid #ecf0f1; }
    table.kv th { width: 180px; color: #7f8c8d; font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.3px; background: #fafafa; }
    .mono-table td { font-family: Consolas, monospace; font-size: 0.85em; word-break: break-all; }
    ul.findings { background: #fff; border: 1px solid #dcdde1; border-radius: 8px; padding: 15px 25px; }
    ul.findings li { margin-bottom: 7px; }
    ul.findings code { background: #f7f9fa; padding: 1px 6px; border-radius: 4px; font-size: 0.9em; }
    .sev { display: inline-block; color: #fff; padding: 1px 7px; border-radius: 4px; font-size: 0.7em; font-weight: 700; text-transform: uppercase; }
    .vt-box { margin: 8px 0; }
    .vt-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 700; color: #fff; }
    .vt-clean { background: #25a244; }
    .vt-mal { background: #e74c3c; }
    .vt-susp { background: #e67e22; }
    .vt-unknown { background: #95a5a6; }
    .footer-note { margin-top: 40px; padding-top: 15px; border-top: 1px solid #dcdde1; color: #7f8c8d; font-size: 0.8em; text-align: center; }
    @media print { .page { padding: 0; } body { background: #fff; } .exec-summary, table.kv, ul.findings { box-shadow: none; } }
    """

    script = f"""
    <script>
        var score = {risk.get('score', 0)};
        var el = document.querySelector('.score-box');
        if (el) el.style.setProperty('--p', score);
    </script>
    """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MalwareLens Report — {html_escape(results.get('info', {}).get('filename', 'sample'))}</title>
<style>{css}</style>
</head>
<body>
<div class="page">
{body}
</div>
{script}
</body>
</html>"""


def generate_json_report(results):
    """Return a JSON export of the analysis results for interoperability."""
    data = {
        "generated": datetime.utcnow().isoformat() + "Z",
        "tool": "MalwareLens",
        "version": "3.0",
        "risk": results.get("risk"),
        "file_info": results.get("info"),
        "hashes": results.get("hashes"),
        "file_type": results.get("file_type"),
        "indicators": {
            "urls": results.get("urls"),
            "ips": results.get("ips"),
            "commands": results.get("commands"),
            "pattern_matches": results.get("pattern_matches"),
        },
        "pe": results.get("pe"),
        "elf": results.get("elf"),
        "apk": results.get("apk"),
        "virustotal": results.get("virustotal"),
    }
    return json.dumps(data, indent=2, default=str)


def html_escape(value):
    return re.sub(
        r"[&<>\"']",
        lambda m: {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[m.group()],
        str(value),
    )