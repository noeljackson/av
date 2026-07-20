#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        target = urlsplit(self.path)
        if target.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            return
        authorized = self.headers.get("Authorization") == "Bearer openbao-ok"
        query_preserved = target.query == "source=integration"
        status = 200 if target.path == "/verify" and authorized and query_preserved else 403
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"injection":"accepted"}' if status == 200 else b'{"error":"forbidden"}')

    def log_message(self, _format, *_args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8081), Handler).serve_forever()
