"""Headless-browser execution proof for xssforge (Selenium + Chromium)."""
import json
import queue
import secrets
import shutil
import threading
import time
from urllib.parse import urlparse

try:
    from selenium import webdriver
    from selenium.webdriver.common.keys import Keys
    from selenium.webdriver.chrome.options import Options as ChromeOptions
    from selenium.webdriver.chrome.service import Service
    HAVE_SELENIUM = True
except ImportError:
    HAVE_SELENIUM = False

import xf_points


def _is_url_echo_network(entry):
    """True if a proof-log entry is only a network call whose URL contains the
    full page location (typical of analytics beacons echoing document.location).
    These must not count as XSS execution proof."""
    low = entry.lower()
    if not (low.startswith("fetch:") or low.startswith("beacon:")):
        return False
    analytics = ("google-analytics", "googletagmanager", "analytics.google",
                 "doubleclick", "googleadservices", "facebook.com/tr",
                 "googlesyndication", "matomo", "piwik",
                 "hotjar", "segment.io", "mixpanel")
    return any(a in low for a in analytics)


def _exec_logs(logs, token):
    """Proof entries that actually show the canary reaching a JS sink/call.

    Error messages (e.g. `ReferenceError: <canary> is not defined`) and
    analytics URL echoes only prove that script ran, not that XSS executed.
    """
    out = []
    for entry in logs or []:
        s = str(entry)
        if token not in s or _is_url_echo_network(s):
            continue
        if s.lower().startswith("error:"):
            continue
        out.append(s)
    return out


def _init_js(token):
    return """
window.__xf=[];
(function(tok){
  function rec(t,a){try{window.__xf.push(t+':'+Array.prototype.slice.call(a).map(String).join('|'))}catch(e){}}
  try{['alert','confirm','prompt','print'].forEach(function(k){window[k]=function(){rec(k,arguments);return undefined}})}catch(e){}
  try{var ol=console.log;console.log=function(){rec('log',arguments);return ol.apply(console,arguments)}}catch(e){}
  try{window.addEventListener('error',function(e){rec('error',[e.message])})}catch(e){}
  try{var d=Object.getOwnPropertyDescriptor(Element.prototype,'innerHTML');
      if(d&&d.set){Object.defineProperty(Element.prototype,'innerHTML',{configurable:true,get:d.get,set:function(v){if(String(v).indexOf(tok)>=0)rec('innerHTML',[v]);return d.set.call(this,v)}})} }catch(e){}
  try{var ow=document.write;document.write=function(){var s=Array.prototype.join.call(arguments,'');if(s.indexOf(tok)>=0)rec('document.write',[s]);return ow.apply(document,arguments)}}catch(e){}
  try{var dt=Object.getOwnPropertyDescriptor(Document.prototype,'title');if(dt&&dt.set){Object.defineProperty(Document.prototype,'title',{configurable:true,get:dt.get,set:function(v){if(String(v).indexOf(tok)>=0)rec('title',[v]);return dt.set.call(this,v)}})}}catch(e){}
  try{var of=window.fetch;window.fetch=function(u,o){if(String(u).indexOf(tok)>=0)rec('fetch',[u]);return of.apply(this,arguments)}}catch(e){}
  try{var ob=navigator.sendBeacon;navigator.sendBeacon=function(u,d){if(String(u).indexOf(tok)>=0)rec('beacon',[u]);return ob.apply(this,arguments)}}catch(e){}
  try{var oi=Element.prototype.insertAdjacentHTML;if(oi){Element.prototype.insertAdjacentHTML=function(p,h){if(String(h).indexOf(tok)>=0)rec('insertAdjacentHTML',[h]);return oi.call(this,p,h)}}}catch(e){}
  try{var oe=window.eval;window.eval=function(s){if(String(s).indexOf(tok)>=0)rec('eval',[s]);return oe.apply(window,arguments)}}catch(e){}
})('%s');
""" % token


def _poke_js(token):
    return """
(function(t){
  function hit(el){
    try{el.focus&&el.focus()}catch(e){}
    try{el.click&&el.click()}catch(e){}
    ['mouseover','pointerover','pointerrawupdate','mousedown','mouseup','click',
     'focus','input','beforeinput','change','toggle','beforetoggle','beforematch',
     'contentvisibilityautostatechange','pageshow','scrollend','cancel','close',
     'command','formdata','invalid','bounce','animationstart','animationend',
     'transitionend','begin'].forEach(function(ev){
      try{el.dispatchEvent(new Event(ev,{bubbles:true,cancelable:true}))}catch(e){}
    });
  }
  try{
    var els=document.querySelectorAll('a,button,input,select,textarea,div,span,svg,img,video,audio,xss,details,dialog,object,embed,marquee,template,*[onclick],*[onmouseover],*[onfocus],*[onpointerover],*[autofocus],*[onbegin],*[popover],*[onbeforetoggle],*[oncontentvisibilityautostatechange]');
    var n=0;
    for(var i=0;i<els.length&&n<40;i++){
      var html='';try{html=els[i].outerHTML||''}catch(e){}
      if(html.indexOf(t)>=0){
        try{els[i].style&&els[i].style.contentVisibility===''&&(els[i].style.contentVisibility='auto')}catch(e){}
        hit(els[i]);n++;
      }
    }
  }catch(e){}
})('%s')
""" % token


_BLOCK_MARKERS = (
    "just a moment", "checking your browser", "attention required",
    "access denied", "request blocked", "blocked by", "web application firewall",
    "security check", "captcha", "verify you are human", "are you a robot",
    "cf-browser-verification", "cf_chl_opt", "ddos protection", "challenge-platform",
    "enable javascript and cookies", "temporarily blocked", "too many requests",
    "unusual traffic", "bot detection", "forbidden",
)


def _block_reason(driver):
    """Detect WAF/bot challenge pages that silently invalidate browser proof."""
    try:
        title = (driver.title or "").lower()
        text = driver.execute_script(
            "return document.body ? document.body.innerText.slice(0,3000) : ''") or ""
        text = str(text).lower()
        url = (driver.current_url or "").lower()
    except Exception:
        return None
    try:
        if driver.find_elements("css selector", "#cf-challenge-running, .cf-browser-verification, "
                                                 ".g-recaptcha, iframe[src*='challenge'], "
                                                 "iframe[src*='captcha']"):
            return "challenge/captcha element"
    except Exception:
        pass
    blob = "%s %s" % (title, url)
    for marker in _BLOCK_MARKERS:
        if marker in blob:
            return marker
    # Words like "captcha" or "forbidden" also appear on ordinary pages (login
    # forms, docs, error messages), so only trust them as body text when the
    # page looks like a challenge: very little visible text.
    has_login_form = False
    try:
        has_login_form = bool(driver.find_elements(
            "css selector", "input[type=password], form#loginform, form[name*=login i]"))
    except Exception:
        pass
    if len(text) < 1200:
        for marker in _BLOCK_MARKERS:
            # "captcha" appears in ordinary page menus/docs (DVWA, dashboards).
            # Only a real challenge element or "verify you are human" counts;
            # both are handled above / in the title+URL check.
            if marker == "captcha":
                continue
            if marker in text:
                return marker
    return None


class BrowserPool:
    def __init__(self, opts, size=2):
        self.opts = opts
        self.size = max(1, size)
        self._q = queue.Queue()
        self._lock = threading.Lock()
        self._created = 0
        self._all = []
        self._chromedriver = shutil.which("chromedriver")
        self._binary = next((shutil.which(b) for b in
                             ("chromium", "chromium-browser", "google-chrome",
                              "google-chrome-stable") if shutil.which(b)), None)
        self.error = None
        if not HAVE_SELENIUM:
            self.error = "selenium not installed"
        elif not self._chromedriver:
            self.error = "chromedriver not found"
        elif not self._binary:
            self.error = "chromium/chrome not found"

    @property
    def available(self):
        return self.error is None

    def _new_driver(self):
        o = ChromeOptions()
        if not getattr(self.opts, "headed", False):
            o.add_argument("--headless=new")
        o.add_argument("--no-sandbox")
        o.add_argument("--disable-gpu")
        o.add_argument("--disable-dev-shm-usage")
        o.add_argument("--disable-extensions")
        o.add_argument("--mute-audio")
        o.add_argument("--window-size=1366,900")
        o.add_argument("--disable-background-networking")
        o.add_argument("--no-first-run")
        o.add_argument("--no-default-browser-check")
        if self.opts.insecure:
            o.add_argument("--ignore-certificate-errors")
        if getattr(self.opts, "proxy", ""):
            o.add_argument("--proxy-server=%s" % self.opts.proxy)
        if getattr(self.opts, "auth_user", ""):
            pass
        o.binary_location = self._binary
        o.add_experimental_option("excludeSwitches", ["enable-automation"])
        try:
            o.set_capability("unhandledPromptBehavior", "accept")
        except Exception:
            pass
        service = Service(executable_path=self._chromedriver)
        d = webdriver.Chrome(service=service, options=o)
        d.set_page_load_timeout(max(5, int(self.opts.timeout)))
        d.set_script_timeout(max(5, int(self.opts.timeout)))
        return d

    def _acquire(self):
        with self._lock:
            if self._created < self.size:
                self._created += 1
                d = self._new_driver()
                self._all.append(d)
                return d
        return self._q.get(timeout=max(30, self.opts.timeout * 2))

    def _release(self, d):
        try:
            d.get("about:blank")
        except Exception:
            pass
        self._q.put(d)

    def close(self):
        for d in list(self._all):
            try:
                d.quit()
            except Exception:
                pass
        self._all = []

    def verify(self, point, value, token, screenshot_path="", reuse_token=False):
        if not self.available:
            return {"hit": False, "logs": [], "detail": self.error, "error": True}
        # Use a unique canary for EACH verification. The caller reuses one token
        # for all payloads in a point; a stale alert left in a pooled browser's
        # window.__xf from a previous payload could otherwise match that token
        # and produce a false CONFIRMED (seen on escaped contexts).
        # Stored XSS is the exception: the canary was persisted earlier, so the
        # token must be kept to match the already-stored payload.
        if not reuse_token:
            vtok = "zq" + secrets.token_hex(8)
            value = value.replace(token, vtok)
            token = vtok
        kwargs, display = xf_points.build_request(point, value, self.opts)
        try:
            driver = self._acquire()
        except Exception as e:
            self.error = "driver start failed: %s" % str(e)[:160]
            return {"hit": False, "logs": [], "detail": self.error, "error": True}
        logs = []
        detail = ""
        try:
            # Dismiss any alert dialog left open by a previous payload on this
            # pooled driver before navigating.
            try:
                driver.switch_to.alert.dismiss()
            except Exception:
                pass
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument",
                                   {"source": _init_js(token)})
            self._set_cookies(driver, point.url)
            loc = point.location
            if loc in ("query", "fragment", "path"):
                if loc == "query" and getattr(self.opts, "raw_inject", False):
                    try:
                        rr = xf_points.raw_request(kwargs, self.opts.user_agent,
                                                   self.opts.timeout, self.opts.max_body)
                        driver.get("about:blank")
                        driver.execute_script("window.__xf=[];delete document.write;")
                        driver.execute_script(
                            "document.open();document.write(arguments[0]);document.close();",
                            rr.text)
                    except Exception as e:
                        detail = "raw fetch failed: %s" % str(e)[:180]
                        return {"hit": False, "logs": [], "error": True,
                                "detail": detail}
                else:
                    if loc == "fragment":
                        # navigating only the fragment does not re-run page scripts
                        try:
                            driver.get("about:blank")
                        except Exception:
                            pass
                    driver.get(kwargs["url"])
            elif loc == "cookie":
                try:
                    driver.get(self._origin(point.url))
                except Exception:
                    pass
                cookie = dict(point.meta.get("cookies") or {})
                cookie[point.name] = value
                for k, v in cookie.items():
                    try:
                        driver.add_cookie({"name": k, "value": v})
                    except Exception:
                        pass
                driver.get(kwargs["url"])
            else:
                try:
                    driver.get(self._origin(point.url))
                except Exception:
                    pass
                script = self._inject_script(point, kwargs, value)
                driver.execute_script(script)
            blocked = _block_reason(driver)
            if blocked:
                return {"hit": False, "logs": [], "error": True,
                        "blocked": True, "reason": blocked,
                        "detail": "browser blocked by challenge: %s" % blocked}
            time.sleep(0.35)
            try:
                driver.execute_script(_poke_js(token))
            except Exception:
                pass
            logs = self._collect(driver, token, getattr(self.opts, "browser_wait", 3.5))
        except Exception as e:
            detail = "browser error: %s" % str(e)[:180]
            return {"hit": False, "logs": [], "error": True,
                    "detail": detail}
        finally:
            if screenshot_path:
                try:
                    driver.save_screenshot(screenshot_path)
                except Exception:
                    pass
            self._release(driver)
        proof_logs = [x for x in logs if not _is_url_echo_network(str(x))]
        blob = " ".join(str(x) for x in proof_logs)
        exec_logs = _exec_logs(proof_logs, token)
        if exec_logs:
            return {"hit": True, "logs": proof_logs,
                    "detail": "execution: " + " ".join(str(x) for x in exec_logs)[:240]}
        if any("SyntaxError" in str(x) for x in proof_logs):
            return {"hit": False, "logs": logs, "syntax_error": True,
                    "detail": "script executed but payload mangled (SyntaxError): " + blob[:200]}
        if proof_logs:
            return {"hit": False, "logs": proof_logs,
                    "detail": "JS activity without execution proof: " + blob[:200]}
        return {"hit": False, "logs": [], "detail": detail or "no execution"}

    def verify_form(self, url, field, value, submit, token, screenshot_path=""):
        """Fill an on-page form field, click its submit control, and collect proof.

        For DOM-stored sinks (e.g. localStorage -> innerHTML) where the page's
        own submit handler must run, not a synthetically created form.
        """
        if not self.available:
            return {"hit": False, "logs": [], "detail": self.error, "error": True}
        vtok = "zq" + secrets.token_hex(8)
        value = value.replace(token, vtok)
        token = vtok
        try:
            driver = self._acquire()
        except Exception as e:
            self.error = "driver start failed: %s" % str(e)[:160]
            return {"hit": False, "logs": [], "detail": self.error, "error": True}
        detail = ""
        logs = []
        page_text = ""
        try:
            try:
                driver.switch_to.alert.dismiss()
            except Exception:
                pass
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument",
                                   {"source": _init_js(token)})
            self._set_cookies(driver, url)
            driver.get(url)
            el = None
            for _attempt in range(12):
                try:
                    el = driver.find_element("css selector", field)
                    break
                except Exception:
                    try:
                        if field.startswith("#"):
                            el = driver.find_element("id", field[1:])
                        elif field.startswith("name="):
                            el = driver.find_element("name", field[5:])
                    except Exception:
                        el = None
                    if el is not None:
                        break
                    time.sleep(0.3)
            if el is None:
                return {"hit": False, "logs": [], "error": True,
                        "detail": "form field not found: %s" % field}
            try:
                el.clear()
            except Exception:
                pass
            el.send_keys(value)
            btn = None
            if submit:
                try:
                    btn = driver.find_element("css selector", submit)
                except Exception:
                    pass
            has_form = False
            try:
                has_form = driver.execute_script(
                    "return !!(arguments[0].closest && arguments[0].closest('form'))", el)
            except Exception:
                pass
            if btn is None and not submit and has_form:
                # Real form: click its submit control so the page's own handler
                # runs (e.g. localStorage -> innerHTML challenges).
                try:
                    btn = el.find_element(
                        "xpath", "ancestor::form//input[@type='submit' or @type='button']")
                except Exception:
                    try:
                        btn = driver.find_element("css selector", "form input[type=submit]")
                    except Exception:
                        btn = None
            if btn is not None:
                btn.click()
            elif btn is None and not submit:
                # Live textarea with no form: send_keys fires input events. Do
                # NOT press Enter — it appends a newline and can break a
                # single-line JS string context.
                try:
                    driver.execute_script(
                        "arguments[0].dispatchEvent(new Event('input',{bubbles:true}));"
                        "arguments[0].dispatchEvent(new Event('change',{bubbles:true}))", el)
                except Exception:
                    pass
            else:
                if btn is None:
                    btn = el.find_element("xpath", "ancestor::form//input[@type='submit']")
                btn.click()
            time.sleep(0.4)
            try:
                driver.execute_script(_poke_js(token))
            except Exception:
                pass
            logs = self._collect(driver, token, getattr(self.opts, "browser_wait", 3.5))
            try:
                page_text = driver.execute_script(
                    "return document.body ? document.body.innerText : ''") or ""
            except Exception:
                pass
        except Exception as e:
            detail = "browser form error: %s" % str(e)[:180]
            return {"hit": False, "logs": [], "error": True, "detail": detail}
        finally:
            if screenshot_path:
                try:
                    driver.save_screenshot(screenshot_path)
                except Exception:
                    pass
            self._release(driver)
        # Filter out network calls that merely echo the PAGE URL. Analytics
        # (Google Analytics, GTM, etc.) include document.location — which carries
        # the canary in the query — in their beacon URLs. That is NOT script
        # execution; treating it as proof caused false CONFIRMED on reflected
        # (but escaped / non-executable) contexts.
        proof_logs = [x for x in logs if not _is_url_echo_network(str(x))]
        blob = " ".join(str(x) for x in proof_logs)
        win_markers = ("Win!", "Congratulations, you executed", "You solved",
                       "Solved!", "Rate this level")
        for marker in win_markers:
            if marker in page_text:
                return {"hit": True, "logs": logs,
                        "detail": "challenge win marker: %s" % marker}
        exec_logs = _exec_logs(proof_logs, token)
        if exec_logs:
            return {"hit": True, "logs": proof_logs,
                    "detail": "execution: " + " ".join(str(x) for x in exec_logs)[:240]}
        if any("SyntaxError" in str(x) for x in proof_logs):
            return {"hit": False, "logs": logs, "syntax_error": True,
                    "detail": "script executed but mangled (SyntaxError): " + blob[:200]}
        if proof_logs:
            return {"hit": False, "logs": proof_logs,
                    "detail": "JS activity without execution proof: " + blob[:200]}
        return {"hit": False, "logs": logs, "detail": detail or "no execution"}

    def _collect(self, driver, token, timeout=3.5):
        end = time.time() + timeout
        out = []
        while time.time() < end:
            try:
                out = driver.execute_script("return window.__xf||[]") or []
            except Exception:
                out = []
            if token in " ".join(str(x) for x in out):
                return out
            time.sleep(0.25)
        return out

    def _origin(self, url):
        p = urlparse(url)
        return "%s://%s" % (p.scheme, p.netloc)

    def _set_cookies(self, driver, url):
        cookie = getattr(self.opts, "cookie", "")
        if not cookie:
            return
        host = urlparse(url).hostname
        try:
            driver.get(self._origin(url))
        except Exception:
            pass
        for part in cookie.split(";"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            try:
                driver.add_cookie({"name": k.strip(), "value": v.strip(), "domain": host})
            except Exception:
                pass

    def _inject_script(self, point, kwargs, value):
        loc = point.location
        if loc == "multipart-filename":
            # Replay the upload with a File whose name is the payload, so the
            # browser sends a real multipart body with filename="<payload>".
            fields = dict(point.data) if isinstance(point.data, dict) else {}
            body = kwargs.get("data", "") or ""
            target_field = point.name
            js = (
                "(function(){var fd=new FormData();var d=%s;"
                "for(var k in d){if(k!==%s){fd.append(k,d[k]);}}"
                "fd.append(%s,new File(['x'],%s,{type:'text/plain'}));"
                "fetch(%s,{method:%s,body:fd,credentials:'include'})"
                ".then(function(r){return r.text()})"
                ".then(function(t){try{document.open();document.write(t);document.close();}"
                "catch(e){}});})();"
                % (json.dumps(fields), json.dumps(target_field),
                   json.dumps(target_field), json.dumps(value),
                   json.dumps(kwargs["url"]), json.dumps(kwargs["method"]))
            )
            return js
        if loc in ("form", "multipart"):
            fields = dict(point.data) if isinstance(point.data, dict) else {}
            if point.name:
                fields[point.name] = value
            action = kwargs["url"]
            method = kwargs["method"]
            enc = "multipart/form-data" if loc == "multipart" else "application/x-www-form-urlencoded"
            return (
                "var f=document.createElement('form');"
                "f.method=%s;f.action=%s;f.enctype=%s;"
                "var d=%s;for(var k in d){var i=document.createElement('input');"
                "i.name=k;i.value=d[k];f.appendChild(i);}"
                "document.body.appendChild(f);f.submit();"
                % (json.dumps(method), json.dumps(action), json.dumps(enc), json.dumps(fields))
            )
        if loc == "json":
            body = json.dumps(kwargs.get("json"))
            return (
                "fetch(%s,{method:%s,headers:{'Content-Type':'application/json'},"
                "body:%s,credentials:'include'}).then(function(r){return r.text()})"
                ".then(function(t){try{document.open();document.write(t);document.close()}catch(e){}});"
                % (json.dumps(kwargs["url"]), json.dumps(kwargs["method"]), json.dumps(body))
            )
        if loc == "header":
            headers = dict(kwargs.get("headers") or {})
            return (
                "fetch(%s,{method:%s,headers:%s,credentials:'include'})"
                ".then(function(r){return r.text()}).then(function(t){try{document.open();document.write(t);document.close()}catch(e){}});"
                % (json.dumps(kwargs["url"]), json.dumps(kwargs["method"]), json.dumps(headers))
            )
        return "location.href=%s" % json.dumps(kwargs["url"])
