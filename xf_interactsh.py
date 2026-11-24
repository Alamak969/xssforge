"""Interactsh client for out-of-band (blind XSS / OOB) callbacks.

Implements the public interactsh registration + polling protocol directly so the
scanner does not depend on the Go ``interactsh-client`` binary:

  * RSA-2048 key pair generated locally (only the public key leaves the host).
  * ``POST /register`` with public-key, secret-key and correlation-id.
  * Callback URLs are ``<flag>.<correlation-id>.<server>``.
  * ``GET /poll`` returns AES-CFB encrypted interactions; the AES key is wrapped
    with RSA-OAEP(SHA-256) using the local public key.

Requires the ``cryptography`` package (see requirements.txt). When the package
or network is unavailable the class degrades to ``available = False`` and the
scanner keeps working with its built-in collaborator or ``--blind``.
"""
import base64
import json
import secrets
import threading
import time

import requests
import urllib3

urllib3.disable_warnings()

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    _CRYPTO = True
except Exception:  # pragma: no cover - optional dependency
    _CRYPTO = False

DEFAULT_SERVERS = ["oast.fun", "oast.pro", "oast.live", "oast.site",
                   "oast.online", "oast.me"]
# interactsh correlation IDs must be xid-formatted: 20 chars from [0-9a-v].
_ALPHABET = "0123456789abcdefghijklmnopqrstuv"
# nonce uses zbase32; any random suffix works but this matches the Go client.
_ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769"


def _rand(n):
    return "".join(secrets.choice(_ALPHABET) for _ in range(n))


def _nonce(n):
    return "".join(secrets.choice(_ZBASE32) for _ in range(n))


class Interactsh:
    """A minimal, dependency-light interactsh client."""

    def __init__(self, server="", token="", insecure=False, timeout=8.0,
                 scheme="https"):
        self.available = False
        self.error = ""
        self.server = ""
        self.token = token
        self.timeout = timeout
        self.scheme = scheme
        self._lock = threading.Lock()
        self._seen = set()
        self.hits = []
        self.correlation_id = _rand(20)
        self.secret = secrets.token_hex(16)
        self.domain = ""
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "xssforge-interactsh/1.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        if token:
            self.session.headers["Authorization"] = token
        if not _CRYPTO:
            self.error = "cryptography package missing (pip install cryptography)"
            return
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = self._key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        self.public_key = base64.b64encode(pem).decode()
        candidates = [server] if server else list(DEFAULT_SERVERS)
        for srv in candidates:
            srv = srv.strip().lstrip(".").replace("https://", "").replace("http://", "")
            srv = srv.rstrip("/")
            if not srv:
                continue
            if self._register(srv):
                self.available = True
                break
        if not self.available and not self.error:
            self.error = "could not register with any interactsh server"

    # -- protocol ---------------------------------------------------------
    def _register(self, server):
        self.server = server
        self.domain = "%s.%s" % (self.correlation_id, server)
        body = {"public-key": self.public_key, "secret-key": self.secret,
                "correlation-id": self.correlation_id}
        for scheme in ("https", "http"):
            url = "%s://%s/register" % (scheme, server)
            try:
                r = self.session.post(url, json=body, timeout=self.timeout,
                                      verify=False)
                if r.status_code == 200 and "success" in (r.text or "").lower():
                    self.scheme = scheme
                    return True
            except Exception as e:
                self.error = str(e)[:160]
        return False

    def _decrypt(self, aes_key_b64, data_b64):
        aes_key = self._key.decrypt(
            base64.b64decode(aes_key_b64),
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None))
        raw = base64.b64decode(data_b64)
        iv, ct = raw[:16], raw[16:]
        dec = Cipher(algorithms.AES(aes_key), modes.CTR(iv)).decryptor()
        plain = dec.update(ct) + dec.finalize()
        return json.loads(plain.decode("utf-8", "replace"))

    def poll(self):
        if not self.available:
            return []
        url = "%s://%s/poll?id=%s&secret=%s" % (
            self.scheme, self.server, self.correlation_id, self.secret)
        try:
            r = self.session.get(url, timeout=self.timeout, verify=False)
            obj = r.json()
        except Exception as e:
            self.error = str(e)[:160]
            return []
        out = []
        aes_key = obj.get("aes_key") or obj.get("aes-key")
        for item in obj.get("data") or []:
            try:
                if aes_key:
                    out.append(self._decrypt(aes_key, item))
                else:
                    out.append(json.loads(base64.b64decode(item)))
            except Exception:
                continue
        for item in obj.get("extra") or []:
            if isinstance(item, dict):
                out.append(item)
        with self._lock:
            for item in out:
                fid = str(item.get("full-id") or item.get("unique-id") or "")
                if fid and fid not in self._seen:
                    self._seen.add(fid)
                    item["_seen_at"] = time.time()
                    self.hits.append(item)
        return out

    def new_flag(self, length=13):
        return _nonce(length)

    def url_for(self, flag, scheme="http"):
        # callback subdomain = correlation-id + nonce (per the interactsh protocol)
        return "%s://%s%s.%s" % (scheme, self.correlation_id, flag, self.server)

    def hits_for(self, flag):
        with self._lock:
            return [h for h in self.hits if flag in str(h.get("full-id", "")).lower()
                    or flag in json.dumps(h, default=str).lower()]

    def wait(self, flag, timeout=8.0, interval=1.0):
        end = time.time() + timeout
        while time.time() < end:
            self.poll()
            hits = self.hits_for(flag)
            if hits:
                return hits
            time.sleep(interval)
        self.poll()
        return self.hits_for(flag)

    def stop(self):
        if not self.available:
            return
        try:
            self.session.post("%s://%s/deregister" % (self.scheme, self.server),
                              json={"correlation-id": self.correlation_id,
                                    "secret-key": self.secret},
                              timeout=self.timeout, verify=False)
        except Exception:
            pass
