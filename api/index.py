"""Vercel Python serverless entry point.

Vercel's Python runtime invokes an :class:`http.server.BaseHTTPRequestHandler`
subclass. Flasks is a WSGI app, so here the raw request is translated into a
WSGI ``environ`` and the app's response is streamed back to the platform.

Important deviations from a normal Flask deployment (platform-imposed):
  * The request body limit is far below the 100 MB the app allows locally —
    only small samples can be analyzed on Vercel.
  * The filesystem is ephemeral and /tmp-backed (see MALWARELENS_*_DIR env in
    vercel.json), so report history does not persist between requests.
"""

import sys
from http.server import BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app


class handler(BaseHTTPRequestHandler):
    def _dispatch(self):
        environ = {
            "REQUEST_METHOD": self.command,
            "SCRIPT_NAME": "",
            "PATH_INFO": self.path.split("?", 1)[0].encode("latin-1").decode("utf-8"),
            "QUERY_STRING": self.path.split("?", 1)[1] if "?" in self.path else "",
            "SERVER_NAME": self.headers.get("Host", "localhost"),
            "SERVER_PORT": str(self.request.server.server_port) if self.server else "443",
            "SERVER_PROTOCOL": self.request_version,
            "wsgi.version": (1, 0),
            "wsgi.version_str": "1.0",
            "wsgi.url_scheme": "https",
            "wsgi.errors": sys.stderr,
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "wsgi.input": self.rfile,
            "CONTENT_LENGTH": self.headers.get("Content-Length", "0"),
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
        }
        for raw_key, value in self.headers.items():
            key = "HTTP_" + raw_key.upper().replace("-", "_")
            environ[key] = value

        captured = {"status": "200 OK", "headers": []}

        def start_response(status, response_headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = [
                (k, str(v)) for k, v in response_headers
                if k.lower() not in ("content-length", "connection")
            ]

        parts = app.wsgi_app(environ, start_response)
        body = b"".join(parts)

        self.send_response(int(captured["status"].split(" ", 1)[0]),
                           captured["status"].split(" ", 1)[1] if " " in captured["status"] else None)
        for k, v in captured["headers"]:
            if k.lower() == "content-type":
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self):
        self._dispatch()

    def do_POST(self):
        self._dispatch()