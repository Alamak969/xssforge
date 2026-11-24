"""Same-origin crawler for xssforge: links, forms, JS endpoints, sitemap."""
import re
from collections import deque
from urllib.parse import urlparse, urljoin, urlunparse, parse_qsl

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

JS_ENDPOINT_RE = re.compile(r"""["'`](\/[A-Za-z0-9_\-./?=&%{}:]+)["'`]""")
JS_URL_RE = re.compile(r"""["'`](https?://[^"'`\s]+)["'`]""")
QUERY_RE = re.compile(r"[?&]([A-Za-z0-9_\-\[\]]+)=")

SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".css",
            ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".webm",
            ".pdf", ".zip", ".gz", ".rar", ".7z", ".exe", ".dmg")

# Following a logout link destroys the authenticated session, after which every
# remaining point looks "not reflected" and browser proof cannot work.
DANGER_PATHS = ("logout", "logoff", "signout", "sign-out", "session_destroy",
                "/exit", "/quit")


class Crawler:
    def __init__(self, session, opts):
        self.session = session
        self.opts = opts
        self.seed_host = urlparse(opts.url).netloc.lower()
        self.urls = []
        self.forms = []
        self.notes = []
        self._seen_urls = set()
        self._seen_forms = set()

    def _same_scope(self, url):
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.netloc.lower()
        if host == self.seed_host:
            return True
        if getattr(self.opts, "crawl_subdomains", False):
            root = ".".join(self.seed_host.split(".")[-2:])
            return host == root or host.endswith("." + root)
        return False

    def _clean(self, url):
        url = url.split("#", 1)[0]
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, "", p.query, ""))

    def _add_url(self, url):
        if not url:
            return
        url = self._clean(url)
        if not self._same_scope(url):
            return
        low = url.lower()
        if any(p in low for p in DANGER_PATHS):
            return
        if low.endswith(SKIP_EXT):
            return
        if url in self._seen_urls:
            return
        self._seen_urls.add(url)
        self.urls.append(url)

    def _add_form(self, base_url, soup_form):
        action = soup_form.get("action") or base_url
        action = urljoin(base_url, action)
        method = (soup_form.get("method") or "get").upper()
        if not self._same_scope(action):
            return
        fields = []
        for el in soup_form.find_all(["input", "textarea", "select"]):
            name = el.get("name")
            if not name:
                continue
            value = el.get("value") or ""
            if el.name == "textarea":
                value = el.get_text() or ""
            fields.append((name, value))
        if not fields:
            return
        sig = (action, method, tuple(n for n, _ in fields))
        if sig in self._seen_forms:
            return
        self._seen_forms.add(sig)
        self.forms.append({"action": action, "method": method, "fields": fields})

    def _parse(self, base_url, text):
        if BeautifulSoup is not None:
            try:
                soup = BeautifulSoup(text, "lxml")
            except Exception:
                soup = BeautifulSoup(text, "html.parser")
            for form in soup.find_all("form"):
                self._add_form(base_url, form)
            for tag, attr in (("a", "href"), ("area", "href"), ("link", "href"),
                              ("script", "src"), ("iframe", "src"),
                              ("frame", "src"), ("img", "src"),
                              ("source", "src"), ("video", "src"),
                              ("audio", "src"), ("form", "action")):
                for el in soup.find_all(tag):
                    val = el.get(attr)
                    if val:
                        self._add_url(urljoin(base_url, val))
            for el in soup.find_all("meta"):
                if (el.get("http-equiv") or "").lower() == "refresh":
                    m = re.search(r"url=(.+)", el.get("content") or "", re.I)
                    if m:
                        self._add_url(urljoin(base_url, m.group(1).strip()))
            for script in soup.find_all("script"):
                if script.get("src"):
                    self._add_url(urljoin(base_url, script["src"]))
                if script.string:
                    self._js_endpoints(base_url, script.string)
        else:
            for m in re.finditer(r"""<form[^>]*action=["']?([^"'\s>]+)""", text, re.I):
                self._add_url(urljoin(base_url, m.group(1)))
            for m in re.finditer(r"""(?:href|src|action)=["']([^"']+)""", text, re.I):
                self._add_url(urljoin(base_url, m.group(1)))
        # query params without an href (plain text / JS templates)
        for m in re.finditer(r"""["'`]([^"'`\s]*\?[^"'`\s]+)["'`]""", text):
            cand = m.group(1)
            if cand.startswith(("http://", "https://", "/")):
                self._add_url(urljoin(base_url, cand))

    def _js_endpoints(self, base_url, js):
        for m in JS_ENDPOINT_RE.finditer(js):
            endpoint = m.group(1)
            if any(ch in endpoint for ch in "${}"):
                continue
            self._add_url(urljoin(base_url, endpoint))
        for m in JS_URL_RE.finditer(js):
            self._add_url(m.group(1))

    def run(self, seed_urls=None):
        seeds = seed_urls or [self.opts.url]
        for s in seeds:
            self._add_url(s)
        queue = deque((u, 0) for u in list(self.urls))
        pages = 0
        max_pages = getattr(self.opts, "crawl_max_pages", 50)
        max_depth = getattr(self.opts, "crawl_depth", 2)
        # sitemap hint
        p = urlparse(self.opts.url)
        origin = "%s://%s" % (p.scheme, p.netloc)
        for hint in ("/robots.txt", "/sitemap.xml"):
            if pages >= max_pages:
                break
            try:
                r = self.session.get(origin + hint, timeout=self.opts.timeout,
                                     verify=not self.opts.insecure)
                if r.status_code == 200:
                    for line in r.text.splitlines():
                        line = line.strip()
                        if line.lower().startswith("sitemap:"):
                            line = line.split(":", 1)[1].strip()
                        if line.startswith("/") or line.startswith("http"):
                            self._add_url(urljoin(origin, line))
                        for loc in re.findall(r"<loc>([^<]+)</loc>", line):
                            self._add_url(loc)
                    pages += 1
            except Exception:
                pass
        for u in list(self.urls):
            if u not in {x[0] for x in queue}:
                queue.append((u, 0))
        fetched = set()
        while queue and pages < max_pages:
            url, depth = queue.popleft()
            if url in fetched:
                continue
            fetched.add(url)
            pages += 1
            try:
                r = self.session.get(url, timeout=self.opts.timeout,
                                     verify=not self.opts.insecure,
                                     allow_redirects=True)
            except Exception as e:
                self.notes.append("crawl error %s: %s" % (url, e))
                continue
            ctype = r.headers.get("Content-Type", "")
            if "html" in ctype or not ctype:
                before = len(self.urls)
                self._parse(url, r.text or "")
                if depth < max_depth:
                    skip_ext = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css",
                                ".ico", ".woff", ".woff2", ".ttf", ".mp4",
                                ".mp3", ".pdf", ".zip", ".webp", ".avif")
                    for nu in self.urls[before:]:
                        path = urlparse(nu).path.lower()
                        if path.endswith(skip_ext):
                            continue
                        if self._same_scope(nu):
                            queue.append((nu, depth + 1))
            elif "javascript" in ctype or url.endswith(".js"):
                self._js_endpoints(url, r.text or "")
            if getattr(self.opts, "delay", 0):
                import time
                time.sleep(self.opts.delay)
        return self.result()

    def result(self):
        return {"urls": self.urls, "forms": self.forms, "notes": self.notes}
