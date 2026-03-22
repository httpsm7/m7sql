"""
m7sql.brain.fingerprinter — Response Fingerprinter
Baselines normal response, detects anomalies caused by injection.
Time-based: requires 5 consistent delays (not random latency).
"""

import time
import hashlib
import statistics
import urllib.request
import urllib.error
from urllib.parse import urlparse


class ResponseFingerprinter:

    def __init__(self, timeout=15, proxy=None):
        self.timeout = timeout
        self.proxy   = proxy

    def baseline(self, url: str, headers: dict = None, count: int = 3) -> dict:
        """
        Collect baseline response metrics.
        Returns: {size, time_avg, time_std, status, hash, content_type}
        """
        times, sizes, statuses = [], [], []
        body_sample = ""

        for _ in range(count):
            t0 = time.time()
            resp = self._fetch(url, headers or {})
            elapsed = time.time() - t0

            if resp:
                times.append(elapsed)
                sizes.append(resp["size"])
                statuses.append(resp["status"])
                if not body_sample:
                    body_sample = resp["body"][:500]
            else:
                times.append(self.timeout)
                sizes.append(0)
                statuses.append(0)

            time.sleep(0.3)  # small gap between baseline requests

        return {
            "url":          url,
            "time_avg":     statistics.mean(times) if times else self.timeout,
            "time_std":     statistics.stdev(times) if len(times) > 1 else 0,
            "size_avg":     statistics.mean(sizes) if sizes else 0,
            "size_std":     statistics.stdev(sizes) if len(sizes) > 1 else 0,
            "status":       statuses[0] if statuses else 0,
            "body_hash":    hashlib.md5(body_sample.encode()).hexdigest(),
            "body_sample":  body_sample,
            "count":        count,
        }

    def check_time_based(self, url: str, payload_url: str,
                         headers: dict, sleep_secs: int = 5,
                         baseline: dict = None, verify_count: int = 5) -> dict:
        """
        Time-based blind injection check.
        Requires consistent delay across verify_count requests.
        Single delay = network noise → rejected.
        """
        if baseline is None:
            baseline = self.baseline(url, headers)

        base_avg = baseline["time_avg"]
        delays   = []

        for i in range(verify_count):
            t0      = time.time()
            resp    = self._fetch(payload_url, headers)
            elapsed = time.time() - t0
            delays.append(elapsed)
            time.sleep(0.5)

        if not delays:
            return {"confirmed": False, "reason": "no responses"}

        avg_delay = statistics.mean(delays)
        std_delay = statistics.stdev(delays) if len(delays) > 1 else 0

        # All delays must be consistently > baseline + sleep_secs
        threshold     = base_avg + sleep_secs * 0.8
        consistent    = all(d >= threshold for d in delays)
        low_variance  = std_delay < 2.0  # not random network noise

        confirmed = consistent and low_variance and avg_delay > threshold

        return {
            "confirmed":    confirmed,
            "avg_delay":    round(avg_delay, 2),
            "base_avg":     round(base_avg, 2),
            "std_delay":    round(std_delay, 2),
            "delays":       [round(d, 2) for d in delays],
            "threshold":    round(threshold, 2),
            "consistent":   consistent,
            "low_variance": low_variance,
            "reason":       "confirmed" if confirmed else (
                "inconsistent delays (network noise)" if not consistent
                else "high variance (not reliable)"
            ),
        }

    def check_boolean_based(self, url_true: str, url_false: str,
                            headers: dict, baseline: dict = None) -> dict:
        """
        Boolean-based blind check.
        true_response != false_response → potential injection.
        """
        if baseline is None:
            baseline = self.baseline(url_true, headers, count=2)

        resp_true  = self._fetch(url_true,  headers)
        resp_false = self._fetch(url_false, headers)

        if not resp_true or not resp_false:
            return {"confirmed": False, "reason": "fetch failed"}

        size_diff = abs(resp_true["size"] - resp_false["size"])
        size_pct  = size_diff / max(resp_true["size"], 1) * 100

        status_diff   = resp_true["status"] != resp_false["status"]
        size_diff_sig = size_pct > 5.0  # >5% size difference
        hash_diff     = (hashlib.md5(resp_true["body"][:200].encode()).hexdigest() !=
                         hashlib.md5(resp_false["body"][:200].encode()).hexdigest())

        # Must be different from baseline too (not just different from each other)
        baseline_diff = abs(resp_true["size"] - baseline["size_avg"]) / max(baseline["size_avg"], 1) * 100

        confirmed = (status_diff or size_diff_sig) and baseline_diff > 2.0

        return {
            "confirmed":      confirmed,
            "size_true":      resp_true["size"],
            "size_false":     resp_false["size"],
            "size_diff_pct":  round(size_pct, 1),
            "status_diff":    status_diff,
            "hash_diff":      hash_diff,
            "reason":         "confirmed" if confirmed else "no significant difference",
        }

    def check_error_based(self, url: str, headers: dict) -> dict:
        """Fetch and return response for error analysis."""
        resp = self._fetch(url, headers)
        if not resp:
            return {"body": "", "status": 0, "size": 0}
        return resp

    def _fetch(self, url: str, headers: dict) -> dict | None:
        """HTTP GET with timeout, returns {body, size, status}."""
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent",
                "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0")
            for k, v in headers.items():
                req.add_header(k, v)

            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read().decode("utf-8", errors="ignore")
                return {
                    "body":   body,
                    "size":   len(body),
                    "status": r.status,
                }
        except urllib.error.HTTPError as e:
            # Still useful — 500 on injection is a signal
            try:
                body = e.read().decode("utf-8", errors="ignore")
            except Exception:
                body = ""
            return {"body": body, "size": len(body), "status": e.code}
        except Exception:
            return None
