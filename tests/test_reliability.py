"""Reliability regression tests using only local loopback fixtures."""
import os
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import xf_points
import xssforge as X


class SlowHandler(BaseHTTPRequestHandler):
    hits = 0
    lock = threading.Lock()

    def do_GET(self):
        with SlowHandler.lock:
            SlowHandler.hits += 1
        time.sleep(2.0)
        try:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        except Exception:
            pass

    def log_message(self, *args):
        pass


class ReliabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=3)

    def test_slow_target_respects_timeout_and_bounded_retries(self):
        SlowHandler.hits = 0
        opts = X.Options(timeout=0.5, retries=1, delay=0.0, follow=True)
        point = xf_points.Point(label="query:q", method="GET",
                                url="http://127.0.0.1:%d/?q=x" % self.port,
                                location="query", name="q", data={"q": "x"})
        factory = X.SessionFactory(opts)
        limiter = X.RateLimiter(opts.delay)
        started = time.time()
        result = X.send(factory, limiter, point, "x", opts)
        elapsed = time.time() - started
        self.assertTrue(isinstance(result, Exception) or getattr(result, "status_code", 0) == 200)
        self.assertLess(elapsed, 2.5, "slow target blocked for %.1fs" % elapsed)
        self.assertEqual(SlowHandler.hits, 1)
        self.assertEqual(factory.request_count, 1)

    def test_peak_memory_metric_available(self):
        self.assertIsInstance(X._peak_memory_mb(), (int, float, type(None)))


if __name__ == "__main__":
    unittest.main()
