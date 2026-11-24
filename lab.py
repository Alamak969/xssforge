#!/usr/bin/env python3
"""Local practice lab for xssforge.

Deliberately vulnerable. Binds to 127.0.0.1 only - use it to validate the
scanner; never expose it.
"""
import html
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
STORED = []
BLIND = []

INDEX = """<html><body><h1>xssforge local lab</h1><ul>
<li><a href="/reflected?q=hi">/reflected?q=</a> - HTML context</li>
<li><a href="/escaped?q=hi">/escaped?q=</a> - negative: HTML-escaped output</li>
<li><a href="/plain?q=hi">/plain?q=</a> - negative: text/plain output</li>
<li><a href="/attr?q=hi">/attr?q=</a> - double-quoted attribute</li>
<li><a href="/attr_sq?q=hi">/attr_sq?q=</a> - single-quoted attribute</li>
<li><a href="/attr_uq?q=hi">/attr_uq?q=</a> - unquoted attribute</li>
<li><a href="/script?q=hi">/script?q=</a> - inside JS string</li>
<li><a href="/script_code?q=1">/script_code?q=</a> - raw JS</li>
<li><a href="/url?q=/next">/url?q=</a> - href sink</li>
<li><a href="/src?q=/x">/src?q=</a> - img src sink</li>
<li><a href="/dom?q=hi">/dom?q=</a> - innerHTML sink</li>
<li><a href="/domhash">/domhash</a> - location.hash -> innerHTML</li>
<li><a href="/comment?q=hi">/comment?q=</a> - HTML comment</li>
<li><a href="/style?q=hi">/style?q=</a> - CSS context</li>
<li><a href="/textarea?q=hi">/textarea?q=</a> - RCDATA</li>
<li><a href="/json?q=hi">/json?q=</a> - JSON response</li>
<li><a href="/form">/form</a> - POST form</li>
<li><a href="/search">/search</a> - GET form</li>
<li><a href="/stored">/stored</a> - stored XSS</li>
<li><a href="/blind">/blind?q=</a> - blind (render: /blind/view)</li>
<li><a href="/header">/header</a> - header reflection (X-XSS)</li>
<li><a href="/cookie">/cookie</a> - cookie reflection (xss)</li>
<li><a href="/path/hello">/path/&lt;value&gt;</a> - path reflection</li>
<li><a href="/waf?q=hi">/waf?q=</a> - naive filter blocks "script"</li>
<li><a href="/waf_attr?q=hi">/waf_attr?q=</a> - filter blocks "alert" in attribute</li>
</ul></body></html>"""


class H(BaseHTTPRequestHandler):
    server_version = "xssforge-lab/1.0"

    def _send(self, body, ctype="text/html; charset=utf-8", status=200, extra=None):
        data = body.encode("utf-8", "replace")
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _cookie(self, name):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                if k.strip() == name:
                    return v.strip()
        return ""

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query, keep_blank_values=True)
        v = q.get("q", [""])[0]
        p = u.path
        if p == "/":
            self._send(INDEX)
        elif p == "/reflected":
            self._send("<html><body><h1>Search</h1><div>%s</div></body></html>" % v)
        elif p == "/escaped":
            safe = html.escape(v, quote=True)
            self._send("<html><body><div>%s</div></body></html>" % safe)
        elif p == "/plain":
            self._send(v, "text/plain; charset=utf-8")
        elif p == "/attr":
            self._send('<html><body><input type="text" name="q" value="%s"></body></html>' % v)
        elif p == "/attr_sq":
            self._send("<html><body><input type='text' value='%s'></body></html>" % v)
        elif p == "/attr_uq":
            self._send("<html><body><input type=text value=%s></body></html>" % v)
        elif p == "/script":
            self._send('<html><body><script>var q="%s";document.write(q);</script></body></html>' % v)
        elif p == "/script_code":
            self._send('<html><body><script>%s</script></body></html>' % v)
        elif p == "/url":
            self._send('<html><body><a href="%s">link</a></body></html>' % v)
        elif p == "/src":
            self._send('<html><body><img src="%s"></body></html>' % v)
        elif p == "/dom":
            self._send("<html><body><div id=o></div><script>document.getElementById('o').innerHTML='%s'</script></body></html>" % v)
        elif p == "/domhash":
            self._send("<html><body><div id=o></div><script>document.getElementById('o').innerHTML=decodeURIComponent(location.hash.substring(1))</script></body></html>")
        elif p == "/comment":
            self._send("<html><body><!-- %s --><p>hi</p></body></html>" % v)
        elif p == "/style":
            self._send("<html><head><style>body{color:%s}</style></head><body>x</body></html>" % v)
        elif p == "/textarea":
            self._send("<html><body><textarea>%s</textarea></body></html>" % v)
        elif p == "/json":
            self._send(json.dumps({"q": v, "ok": True}), "application/json")
        elif p == "/search":
            self._send('<html><body><form action="/search" method="get">'
                       '<input name="q"><input type="submit"></form></body></html>')
        elif p == "/form":
            self._send('<html><body><form action="/form" method="post">'
                       '<input name="comment"><input name="nick"><input type="submit"></form></body></html>')
        elif p == "/stored":
            body = "".join("<div>%s</div>" % x for x in STORED)
            self._send('<html><body><form action="/stored" method="post">'
                       '<input name="comment"><input type="submit"></form>%s</body></html>' % body)
        elif p == "/stored/view":
            self._send("<html><body>%s</body></html>" %
                       "".join("<p>%s</p>" % x for x in STORED))
        elif p == "/blind":
            if v:
                BLIND.append(v)
            self._send("<html><body>stored. view: <a href=/blind/view>here</a></body></html>")
        elif p == "/blind/view":
            self._send("<html><body>%s</body></html>" %
                       "".join("<p>%s</p>" % x for x in BLIND))
        elif p == "/header":
            self._send("<html><body><pre>%s</pre></body></html>" % self.headers.get("X-XSS", ""))
        elif p == "/cookie":
            self._send("<html><body><pre>%s</pre></body></html>" % self._cookie("xss"))
        elif p.startswith("/path/"):
            seg = unquote_plus(p[len("/path/"):])
            self._send("<html><body><div>%s</div></body></html>" % seg)
        elif p == "/waf_attr":
            if "alert" in v.lower():
                self._send("<html><body>blocked</body></html>", status=403,
                           extra={"Server": "dx-waf/1.0"})
            else:
                self._send('<html><body><input type="text" value="%s"></body></html>' % v)
        elif p == "/waf":
            if "script" in v.lower() or "<" in v:
                self._send("<html><body>Request blocked by security policy</body></html>",
                           status=403, extra={"Server": "dx-waf/1.0"})
            else:
                self._send("<html><body><div>%s</div></body></html>" % v)
        else:
            self.send_error(404)

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        p = urlparse(self.path).path
        ctype = self.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                data = json.loads(raw)
            except Exception:
                data = {}
            v = str(data.get("q", ""))
            self._send("<html><body><div>%s</div></body></html>" % v)
            return
        form = parse_qs(raw)
        if p == "/form":
            v = form.get("comment", [""])[0]
            self._send("<html><body><h1>Comment</h1><div>%s</div></body></html>" % v)
        elif p == "/stored":
            v = form.get("comment", [""])[0]
            STORED.append(v)
            body = "".join("<div>%s</div>" % x for x in STORED)
            self._send('<html><body><form action="/stored" method="post">'
                       '<input name="comment"><input type="submit"></form>%s</body></html>' % body)
        elif p == "/blind":
            v = form.get("comment", [""])[0]
            BLIND.append(v)
            self._send("<html><body>ok</body></html>")
        else:
            self.send_error(404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("xssforge local lab -> http://127.0.0.1:%d/" % PORT)
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
