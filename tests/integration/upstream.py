#!/usr/bin/env python3
import base64
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote, urlsplit


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        target = urlsplit(self.path)
        if target.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            return
        if target.path == "/tunnel":
            body = b"credentialless-tunnel-ok"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        authorization = self.headers.get_all("Authorization") or []
        authorized = authorization == ["Bearer openbao+ok"]
        query_preserved = target.query == "source=integration"
        forbidden_headers_absent = not any(
            self.headers.get(name)
            for name in ("X-Forwarded-Host", "X-HTTP-Method-Override", "X-Original-URL")
        )
        if target.path == "/verify":
            status = 200 if authorized and query_preserved and forbidden_headers_absent else 403
            body = b'{"injection":"accepted"}' if status == 200 else b'{"error":"forbidden"}'
        elif target.path == "/basic":
            expected = "Basic " + base64.b64encode(b"av-user:openbao+ok").decode()
            status = 200 if authorization == [expected] else 403
            body = expected.encode() if status == 200 else b'{"error":"forbidden"}'
        elif target.path == "/stream" and authorized:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            self.wfile.write(b"data: ready\n\n:" + b"x" * 64 + b"\n\n")
            self.wfile.flush()
            time.sleep(1)
            self.wfile.write(b"data: openbao")
            self.wfile.flush()
            time.sleep(0.1)
            self.wfile.write(b"+ok\n\n")
            self.wfile.flush()
            return
        elif target.path == "/x-header":
            api_keys = self.headers.get_all("X-Api-Key") or []
            status = 200 if api_keys == ["openbao+ok"] and forbidden_headers_absent else 403
            body = b'{"singleHeader":"accepted"}' if status == 200 else b'{"error":"forbidden"}'
        elif target.path == "/encoded" and authorized:
            encoded = base64.b64encode(b"openbao+ok").decode()
            percent = quote("openbao+ok", safe="")
            status = 200
            body = f"openbao+ok|{encoded}|{percent}".encode()
        else:
            status = 403
            body = b'{"error":"forbidden"}'
        self.send_response(status)
        self.send_header("Content-Type", "application/json" if body.startswith(b"{") else "text/plain")
        self.send_header("Location", "https://hostile.example/openbao+ok")
        self.send_header("X-Reflected-Secret", "Bearer openbao+ok")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        target = urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        authorization = self.headers.get_all("Authorization") or []
        accepted = (
            target.path == "/body"
            and authorization == ["Bearer openbao+ok"]
            and body == b'{"token":"openbao+ok"}'
            and self.headers.get_content_type() == "application/json"
        )
        self.send_response(200 if accepted else 403)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body if accepted else b'{"error":"forbidden"}')

    def log_message(self, _format, *_args):
        pass

plain = ThreadingHTTPServer(("0.0.0.0", 8081), Handler)
threading.Thread(target=plain.serve_forever, daemon=True).start()
tls = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/test-tls/tunnel.crt", "/test-tls/tunnel.key")
tls.socket = context.wrap_socket(tls.socket, server_side=True)
tls.serve_forever()
