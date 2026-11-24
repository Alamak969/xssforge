"""Built-in HTTP collaborator (Out-of-Band) for blind XSS."""
import json
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


class _Store:
    def __init__(self):
        self.lock = threading.Lock()
        self.hits = []

    def add(self, item):
        with self.lock:
            self.hits.append(item)

    def for_token(self, token):
        with self.lock:
            return [h for h in self.hits if token in h.get("path", "") or token in h.get("body", "")]


class _Handler(BaseHTTPRequestHandler):
    server_version = "xssforge-oob/1.0"

    def _record(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        self.server.store.add({
            "time": time.time(),
            "method": self.command,
            "path": self.path,
            "client": self.client_address[0] if self.client_address else "",
            "headers": dict(self.headers),
            "body": body[:4000],
        })
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    do_GET = _record
    do_POST = _record
    do_PUT = _record
    do_HEAD = _record

    def log_message(self, *a):
        pass


class Collaborator:
    def __init__(self, host="0.0.0.0", port=8888, public_url=""):
        self.host = host
        self.port = port
        self.store = _Store()
        self.server = None
        self.thread = None
        self.public_url = public_url or ("http://%s:%d" % (
            "127.0.0.1" if host in ("0.0.0.0", "") else host, port))
        self._tokens = {}

    def start(self):
        self.server = ThreadingHTTPServer((self.host, self.port), _Handler)
        self.server.store = self.store
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass

    def new_token(self, label="x"):
        token = "%s%s" % (label, secrets.token_hex(6))
        self._tokens[token] = label
        return token

    def url_for(self, token):
        return "%s/%s" % (self.public_url.rstrip("/"), token)

    def hits_for(self, token):
        return self.store.for_token(token)

    def all_hits(self):
        return list(self.store.hits)

    def wait(self, token, timeout=8.0, interval=0.5):
        end = time.time() + timeout
        while time.time() < end:
            hits = self.hits_for(token)
            if hits:
                return hits
            time.sleep(interval)
        return self.hits_for(token)
