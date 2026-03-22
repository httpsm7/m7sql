"""m7sql.core.rate_limit — Rate Control"""
import time, random, threading
from collections import defaultdict


class RateLimitEngine:
    def __init__(self, default_rps=3, circuit_threshold=5, circuit_reset=30):
        self.rps        = default_rps
        self.threshold  = circuit_threshold
        self.reset_time = circuit_reset
        self._lock      = threading.Lock()
        self._last      = defaultdict(float)
        self._fails     = defaultdict(int)
        self._open      = defaultdict(bool)
        self._since     = defaultdict(float)

    def wait(self, domain):
        with self._lock:
            if self._open[domain]:
                elapsed = time.time() - self._since[domain]
                if elapsed < self.reset_time:
                    raise RuntimeError(f"Circuit OPEN: {domain}")
                self._open[domain] = False
                self._fails[domain] = 0
            interval = 1.0 / self.rps
            gap = interval - (time.time() - self._last[domain])
            wait_t = max(0, gap + random.uniform(-0.1, 0.1) * interval)
            if wait_t > 0:
                time.sleep(wait_t)
            self._last[domain] = time.time()

    def ok(self, domain):
        with self._lock:
            self._fails[domain] = 0

    def fail(self, domain, status=0):
        with self._lock:
            self._fails[domain] += 1
            if status == 429:
                backoff = min(2 ** self._fails[domain], 60)
                time.sleep(backoff)
            if self._fails[domain] >= self.threshold:
                self._open[domain] = True
                self._since[domain] = time.time()
