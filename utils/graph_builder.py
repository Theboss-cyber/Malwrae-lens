"""Build a relationship graph from analysis results.

The graph visualizes how the sample connects to indicators found during
analysis: URLs, IP addresses, imports (DLLs), suspicious APIs, dangerous
permissions (APK), etc. Rendered client-side with a small force layout.
"""

import html


class GraphBuilder:
    def __init__(self, results):
        self.results = results
        self.nodes = []
        self.edges = []
        self._node_ids = set()

    def _add_node(self, node_id, label, kind, severity=None, extra=None):
        if node_id in self._node_ids:
            return node_id
        self._node_ids.add(node_id)
        node = {
            "id": node_id,
            "label": label,
            "kind": kind,
        }
        if severity:
            node["severity"] = severity
        if extra:
            node.update(extra)
        self.nodes.append(node)
        return node_id

    def _add_edge(self, source, target, label=""):
        edge = {"source": source, "target": target}
        if label:
            edge["label"] = label
        self.edges.append(edge)

    def build(self):
        """Build graph from results. Returns dict with nodes/edges."""
        file_info = self.results.get("info", {})
        file_node = self._add_node(
            "file", file_info.get("filename", "sample"), "file",
            severity="info",
            extra={"detail": file_info.get("size_human", "")},
        )

        # URLs
        for url in self.results.get("urls", [])[:15]:
            url_id = self._add_node(f"url:{url}", url, "url", severity="medium")
            self._add_edge(file_node, url_id)

        # IPs
        for ip in self.results.get("ips", [])[:15]:
            ip_id = self._add_node(f"ip:{ip}", ip, "ip", severity="high")
            self._add_edge(file_node, ip_id)

        # Commands
        for cmd in self.results.get("commands", [])[:12]:
            cmd_id = self._add_node(f"cmd:{cmd}", cmd, "command", severity="medium")
            self._add_edge(file_node, cmd_id)

        # Pattern matches
        for match in self.results.get("pattern_matches", [])[:12]:
            sev = match.get("severity", "medium")
            pid = self._add_node(
                f"pattern:{match['rule']}", match["rule"], "pattern", severity=sev,
                extra={"detail": match.get("type", "")},
            )
            self._add_edge(file_node, pid)

        # PE analysis
        pe = self.results.get("pe")
        if pe and pe.get("is_valid"):
            for api in pe.get("suspicious_apis", [])[:15]:
                api_id = self._add_node(f"api:{api['api']}", api["api"], "api", severity="high")
                self._add_edge(file_node, api_id)
            suspicious_dlls = set()
            for api in pe.get("suspicious_apis", []):
                suspicious_dlls.add(api.get("dll", ""))
            for dll in list(suspicious_dlls)[:10]:
                dll_id = self._add_node(f"dll:{dll}", dll, "dll", severity="medium")
                self._add_edge(file_node, dll_id)

        # ELF analysis
        elf = self.results.get("elf")
        if elf and elf.get("is_valid"):
            for func in elf.get("suspicious_functions", [])[:15]:
                fid = self._add_node(f"elf_func:{func['function']}", func["function"], "api", severity="high")
                self._add_edge(file_node, fid)

        # APK analysis
        apk = self.results.get("apk")
        if apk and apk.get("is_valid"):
            for perm in apk.get("dangerous_permissions", [])[:15]:
                perm_id = self._add_node(
                    f"perm:{perm['permission']}",
                    perm["permission"].split(".")[-1],
                    "permission",
                    severity="high",
                    extra={"detail": perm["permission"]},
                )
                self._add_edge(file_node, perm_id)

        # File type risk links
        file_type = self.results.get("file_type", {})
        if file_type.get("magic_detected") and file_type.get("extension_match") is False:
            mtid = self._add_node(
                "magic", file_type["magic_detected"], "magic", severity="high",
                extra={"detail": "Magic bytes don't match extension"},
            )
            self._add_edge(file_node, mtid)

        # Add risk level into the file node
        for node in self.nodes:
            if node["id"] == file_node:
                node["severity"] = self.results.get("risk", {}).get("color", "green")
                node["label_short"] = node["label"][:40]
                break

        return {
            "nodes": self.nodes,
            "edges": self.edges,
            "stats": {"nodes": len(self.nodes), "edges": len(self.edges)},
        }


def build_graph(results):
    return GraphBuilder(results).build()