"""Orchestration of the multi-phase analysis pipeline for a single file.

The pipeline is deliberately split into named stages so each responsibility is
isolated and individually testable:

    Stage 1  Static extraction   -> file info, hashes, strings, URLs, IPs,
                                    commands, entropy
    Stage 2  Classification      -> magic-byte type detection + signature scan
    Stage 3  Deep format analysis-> PE / ELF / APK internals (best effort)
    Stage 4  Risk scoring        -> automated, explainable threat score
    Stage 5  Enrichment          -> VirusTotal lookup (degrades offline)
    Stage 6  Visualization       -> indicator relationship graph

Stages 3 and 5 are "soft": a failure there degrades the result instead of
aborting the whole analysis. Everything else surfaces as :class:`AnalysisError`.
"""

from pathlib import Path

from analyzers.apk_analyzer import APKAnalyzer
from analyzers.elf_analyzer import ELFAnalyzer
from analyzers.file_identifier import FileIdentifier
from analyzers.pattern_scanner import PatternScanner
from analyzers.pe_analyzer import PEAnalyzer
from analyzers.static_analyzer import StaticAnalyzer
from utils.graph_builder import build_graph
from utils.risk_scorer import RiskScorer
from utils.virustotal import enrich_with_virustotal

MAX_STRINGS = 200
MAGIC_HEADER_SIZE = 512


class AnalysisError(Exception):
    """Raised when a sample cannot be analyzed at all."""


class AnalysisPipeline:
    """Runs the static-analysis pipeline in clearly separated stages."""

    def __init__(self, file_path):
        self.file_path = Path(file_path)
        self.stat = StaticAnalyzer(self.file_path)

    # ----- Stage 1: static extraction -----
    def _stage_extraction(self):
        return {
            "info": self.stat.get_basic_info(),
            "hashes": self.stat.get_hashes(),
            "strings": self.stat.extract_strings(max_results=MAX_STRINGS),
            "urls": self.stat.extract_urls(),
            "ips": self.stat.extract_ips(),
            "commands": self.stat.extract_commands(),
            "entropy": self.stat.get_entropy(),
        }

    # ----- Stage 2: classification -----
    def _stage_classification(self, filename):
        with open(self.file_path, "rb") as f:
            header = f.read(MAGIC_HEADER_SIZE)
        return {
            "file_type": FileIdentifier(header).detect(filename),
            "pattern_matches": PatternScanner.scan_file(self.file_path),
        }

    # ----- Stage 3: deep format analysis (best effort) -----
    def _stage_deep_analysis(self, advanced, filename):
        type_key = advanced["file_type"].get("type_key", "")

        def _best_effort(kind, fn):
            """Run an analyzer; on any error degrade to an error note."""
            try:
                parsed = fn()
            except Exception as e:  # noqa: BLE001 - degrade, never abort
                parsed = {"error": f"{kind} parse failed: {e}"}
            if not isinstance(parsed, dict):
                parsed = {"error": f"{kind} returned invalid data"}
            if not parsed.get("is_valid", True):
                parsed = {"error": parsed.get("error", f"{kind} parse failed")}
            advanced[kind] = parsed

        if type_key == "pe":
            _best_effort("pe", lambda: PEAnalyzer(self.file_path).analyze())
        elif type_key == "elf":
            _best_effort("elf", lambda: ELFAnalyzer(self.file_path).analyze())
        elif type_key in ("apk", "zip") and filename.lower().endswith(".apk"):
            _best_effort("apk", lambda: APKAnalyzer(self.file_path).analyze())
        return advanced

    # ----- Stage 4: risk scoring -----
    @staticmethod
    def _stage_risk(phase1, advanced):
        return RiskScorer(phase1, advanced).calculate()

    # ----- Stage 5: enrichment (soft fail) -----
    @staticmethod
    def _stage_enrichment(hashes):
        try:
            return enrich_with_virustotal(hashes)
        except Exception as e:  # noqa: BLE001 - never abort analysis
            return {
                "enabled": False,
                "message": f"Threat enrichment unavailable: {e}",
                "file": None,
                "urls": [],
            }

    # ----- assembly -----
    @staticmethod
    def _assemble(phase1, advanced, risk, virustotal):
        return {
            "info": phase1["info"],
            "hashes": phase1["hashes"],
            "strings": phase1["strings"],
            "urls": phase1["urls"],
            "ips": phase1["ips"],
            "commands": phase1["commands"],
            "entropy": phase1["entropy"],
            "risk": risk,
            "file_type": advanced["file_type"],
            "pattern_matches": advanced["pattern_matches"],
            "pe": advanced.get("pe"),
            "elf": advanced.get("elf"),
            "apk": advanced.get("apk"),
            "virustotal": virustotal,
        }

    def run(self):
        """Execute every stage and return the complete analysis result."""
        phase1 = self._stage_extraction()
        filename = phase1["info"].get("filename", self.file_path.name)
        advanced = self._stage_classification(filename)
        advanced = self._stage_deep_analysis(advanced, filename)
        risk = self._stage_risk(phase1, advanced)
        virustotal = self._stage_enrichment(phase1["hashes"])
        result = self._assemble(phase1, advanced, risk, virustotal)
        result["graph"] = build_graph(result)
        return result


class AnalysisService:
    """Entry point the web layer calls to analyze an uploaded sample."""

    def __init__(self, pipeline_cls=None):
        self.pipeline_cls = pipeline_cls or AnalysisPipeline

    def analyze(self, file_path):
        try:
            return self.pipeline_cls(file_path).run()
        except AnalysisError:
            raise
        except Exception as e:
            raise AnalysisError(str(e)) from e