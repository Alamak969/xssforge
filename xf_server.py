"""REST + MCP server modes for xssforge.

REST (``python3 xf_server.py rest --port 8080``):
  POST /scan  {"url": "...", "options": ["--browser", "--libscan", ...]}
  GET  /status/<scan_id>
  GET  /result/<scan_id>
  GET  /health

MCP stdio (``python3 xf_server.py mcp``):
  JSON-RPC over stdin/stdout exposing tools:
    - xss_scan(url, options)  -> run a scan, return summary + report paths
    - xss_list_reports()      -> list saved reports

Both modes run the real xssforge engine in a background thread/process.
"""
import argparse
import json
import os
import subprocess
import sys
import threading
import time
import uuid

BASE = os.path.dirname(os.path.abspath(__file__))
SCANS = {}
SCANS_LOCK = threading.Lock()


def _run_scan(scan_id, url, options):
    outdir = os.path.join(BASE, "server-out", scan_id)
    os.makedirs(outdir, exist_ok=True)
    cmd = [sys.executable, os.path.join(BASE, "xssforge.py"),
           "-u", url, "--authorized"] + list(options or []) + [
           "--quiet", "--output-dir", outdir]
    entry = SCANS[scan_id]
    entry["status"] = "running"
    entry["command"] = " ".join(cmd)
    try:
        p = subprocess.run(cmd, cwd=BASE, capture_output=True, text=True, timeout=900)
        entry["stdout"] = p.stdout[-20000:]
        entry["stderr"] = p.stderr[-8000:]
        entry["returncode"] = p.returncode
        reports = []
        for root, dirs, files in os.walk(outdir):
            for f in files:
                if f.startswith("report-"):
                    reports.append(os.path.join(root, f))
        entry["reports"] = reports
        # parse summary from the JSON report if available
        for rp in reports:
            if rp.endswith(".json"):
                try:
                    d = json.load(open(rp))
                    entry["summary"] = d.get("summary")
                    entry["results"] = d.get("results")
                    break
                except Exception:
                    pass
        entry["status"] = "done" if p.returncode == 0 else "error"
    except subprocess.TimeoutExpired:
        entry["status"] = "timeout"
    except Exception as e:
        entry["status"] = "error"
        entry["stderr"] = str(e)


def start_scan(url, options=None):
    sid = uuid.uuid4().hex[:12]
    with SCANS_LOCK:
        SCANS[sid] = {"id": sid, "url": url, "status": "queued",
                      "created": time.time(), "options": options or []}
    t = threading.Thread(target=_run_scan, args=(sid, url, options or []), daemon=True)
    t.start()
    return sid


# ---------------------------------------------------------------------------
# REST server
# ---------------------------------------------------------------------------

def run_rest(port=8080, host="127.0.0.1"):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlparse

    class H(BaseHTTPRequestHandler):
        def _json(self, obj, code=200):
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            p = urlparse(self.path).path
            if p == "/health":
                return self._json({"ok": True, "tool": "xssforge"})
            if p.startswith("/status/"):
                sid = p.split("/")[-1]
                e = SCANS.get(sid)
                return self._json(e if e else {"error": "not found"},
                                  200 if e else 404)
            if p.startswith("/result/"):
                sid = p.split("/")[-1]
                e = SCANS.get(sid)
                if not e:
                    return self._json({"error": "not found"}, 404)
                return self._json({"id": sid, "status": e["status"],
                                   "summary": e.get("summary"),
                                   "results": e.get("results"),
                                   "reports": e.get("reports", []),
                                   "stdout_tail": e.get("stdout", "")[-4000:]})
            if p == "/scans":
                return self._json(list(SCANS.values()))
            return self._json({"error": "unknown endpoint"}, 404)

        def do_POST(self):
            p = urlparse(self.path).path
            if p != "/scan":
                return self._json({"error": "unknown endpoint"}, 404)
            try:
                n = int(self.headers.get("Content-Length", 0))
                data = json.loads(self.rfile.read(n) or b"{}")
                url = data.get("url", "")
                if not url:
                    return self._json({"error": "url required"}, 400)
                sid = start_scan(url, data.get("options"))
                return self._json({"id": sid, "status": "queued"}, 202)
            except Exception as e:
                return self._json({"error": str(e)}, 400)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer((host, port), H)
    print("xssforge REST server on http://%s:%d" % (host, port), flush=True)
    print("POST /scan  {\"url\":\"...\", \"options\":[\"--browser\",\"--libscan\"]}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


# ---------------------------------------------------------------------------
# MCP stdio server (JSON-RPC 2.0, newline-delimited)
# ---------------------------------------------------------------------------

TOOLS = [
    {"name": "xss_scan",
     "description": "Run an xssforge XSS scan against a URL. Returns scan id.",
     "inputSchema": {"type": "object",
                     "properties": {"url": {"type": "string"},
                                    "options": {"type": "array",
                                                "items": {"type": "string"}}},
                     "required": ["url"]}},
    {"name": "xss_status",
     "description": "Get status/results of a running scan by id.",
     "inputSchema": {"type": "object",
                     "properties": {"id": {"type": "string"}},
                     "required": ["id"]}},
    {"name": "xss_list_reports",
     "description": "List saved xssforge reports.",
     "inputSchema": {"type": "object", "properties": {}}},
]


def run_mcp():
    def reply(rid, result=None, error=None):
        msg = {"jsonrpc": "2.0", "id": rid}
        if error is not None:
            msg["error"] = error
        else:
            msg["result"] = result
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        method = req.get("method")
        rid = req.get("id")
        params = req.get("params") or {}
        if method == "initialize":
            reply(rid, {"protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "xssforge", "version": "1.0"}})
        elif method == "tools/list":
            reply(rid, {"tools": TOOLS})
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "xss_scan":
                sid = start_scan(args.get("url", ""), args.get("options"))
                reply(rid, {"content": [{"type": "text",
                                         "text": json.dumps({"id": sid, "status": "queued"})}]})
            elif name == "xss_status":
                e = SCANS.get(args.get("id"))
                reply(rid, {"content": [{"type": "text",
                                         "text": json.dumps(e or {"error": "not found"},
                                                            default=str)}]})
            elif name == "xss_list_reports":
                reports = []
                for root, dirs, files in os.walk(os.path.join(BASE, "server-out")):
                    for f in files:
                        if f.startswith("report-"):
                            reports.append(os.path.join(root, f))
                reply(rid, {"content": [{"type": "text",
                                         "text": json.dumps(reports)}]})
            else:
                reply(rid, error={"code": -32601, "message": "unknown tool"})
        elif method == "notifications/initialized":
            pass
        else:
            reply(rid, error={"code": -32601, "message": "unknown method"})


def main():
    ap = argparse.ArgumentParser(description="xssforge REST / MCP server")
    sub = ap.add_subparsers(dest="mode", required=True)
    r = sub.add_parser("rest")
    r.add_argument("--port", type=int, default=8080)
    r.add_argument("--host", default="127.0.0.1")
    sub.add_parser("mcp")
    a = ap.parse_args()
    if a.mode == "rest":
        run_rest(a.port, a.host)
    else:
        run_mcp()


if __name__ == "__main__":
    main()
