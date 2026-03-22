"""
m7sql.core.scanner — Smart Scanner
Uses all 7 Brain modules to test injection points intelligently.
Decision tree: Classify → Baseline → Quote → Error/Boolean/Time → Validate
"""

import threading
import time
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs

from m7sql.brain.classifier  import TargetClassifier
from m7sql.brain.error_db    import ErrorBrain
from m7sql.brain.fingerprinter import ResponseFingerprinter
from m7sql.brain.payload_brain import PayloadBrain
from m7sql.brain.validator   import ConfidenceValidator
from m7sql.brain.display     import LiveDisplay


class SmartScanner:

    def __init__(self, args, session):
        self.args      = args
        self.session   = session
        self.threads   = args.threads
        self.timeout   = args.timeout
        self.proxy     = args.proxy
        self.verbose   = args.verbose
        self.scan_id   = args.scan_id

        # Brain modules
        self.classifier   = TargetClassifier()
        self.error_brain  = ErrorBrain()
        self.fingerprinter= ResponseFingerprinter(timeout=self.timeout, proxy=self.proxy)
        self.payload_brain= PayloadBrain()
        self.validator    = ConfidenceValidator()

        self._lock        = threading.Lock()
        self._results     = []
        self._done_keys   = set()

        if args.resume:
            self._load_checkpoint()

    def run(self, injection_points: list) -> list:
        """Main scan loop with full brain intelligence."""

        # ── Phase 1: Classify all points ──────────────────────
        print(f"\n  \033[36m[brain]\033[0m Classifying {len(injection_points)} injection points...")

        testable = []
        skipped  = 0

        for point in injection_points:
            url   = point.get("url", "")
            param = point.get("param", "")
            ptype = point.get("param_type", "GET")

            # URL-level classification
            url_class = self.classifier.classify_url(url)
            if url_class["action"] == "skip":
                skipped += 1
                continue

            # Param-level classification
            param_class = self.classifier.classify_param(param, url)
            if param_class["action"] == "skip":
                skipped += 1
                continue

            # Skip if already done (resume)
            if self._key(point) in self._done_keys:
                skipped += 1
                continue

            point["_priority"]  = url_class["priority"]
            point["_url_type"]  = url_class["url_type"]
            testable.append(point)

        # Sort by priority — high value params first
        testable.sort(key=lambda p: p.get("_priority", 0), reverse=True)

        print(f"  \033[32m[brain]\033[0m {len(testable)} testable | {skipped} skipped (FP prevention)\n")

        if not testable:
            print("  \033[33mNothing to test after classification.\033[0m")
            return []

        # ── Phase 2: Scan with live display ───────────────────
        display = LiveDisplay(
            total_points=len(testable),
            total_urls=len(set(p["url"] for p in testable)),
            skipped=skipped
        )

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(self._test_point, point, display): point
                for point in testable
            }
            for future in as_completed(futures):
                point = futures[future]
                try:
                    result = future.result()
                    if result:
                        with self._lock:
                            self._results.append(result)
                        display.found_vuln(result)
                except Exception as e:
                    if self.verbose:
                        print(f"\n  \033[31m[scanner] Error: {e}\033[0m")
                finally:
                    display.mark_scanned()
                    self._save_checkpoint(point)

        display.finish()
        return self._results

    def _test_point(self, point: dict, display: LiveDisplay) -> dict | None:
        """
        Full brain decision tree for one injection point.
        Returns finding dict or None.
        """
        url    = point.get("url", "")
        param  = point.get("param", "")
        ptype  = point.get("param_type", "GET")
        hdr    = self.session.get_headers()
        dbms   = "generic"

        display.update_current(url, param, "brain", "baseline...")

        # ── Step 1: Baseline ──────────────────────────────────
        baseline = self.fingerprinter.baseline(url, hdr, count=2)
        if baseline["status"] in (301, 302, 303, 307, 308, 404):
            display.mark_rejected()
            return None

        # ── Step 2: Quote probe ───────────────────────────────
        display.update_current(url, param, "brain", "quote probe...")
        error_signal = False

        for quote in self.payload_brain.get_quote_probes():
            probe_url = self.payload_brain.inject_param(url, param, quote)
            resp      = self.fingerprinter.check_error_based(probe_url, hdr)

            if not resp or not resp.get("body"):
                continue

            analysis = self.error_brain.analyze_response(resp["body"], resp.get("status", 200))

            # WAF detected — try bypass
            if analysis["waf_detected"]:
                display.update_current(url, param, "brain",
                                       f"WAF:{analysis['waf_detected']} bypass...")
                result = self._try_waf_bypass(url, param, hdr, analysis, baseline, display)
                if result:
                    return self.validator.validate(result)
                display.mark_rejected()
                return None

            # SQL error confirmed
            if analysis["action"] == "confirmed":
                error_signal = True
                dbms = analysis.get("dbms", "generic")
                break

            # FP detected
            if analysis["is_fp"]:
                display.mark_rejected()
                return None

        # ── Step 3: Error-Based (if quote triggered error) ────
        if error_signal:
            display.update_current(url, param, "sqlmap", "error-based...")
            result = self._test_error_based(url, param, hdr, dbms, baseline)
            if result:
                validated = self.validator.validate(result)
                if validated:
                    return validated

        # ── Step 4: Boolean-Based ─────────────────────────────
        display.update_current(url, param, "sqlmap", "boolean test...")
        result = self._test_boolean(url, param, hdr, baseline)
        if result:
            validated = self.validator.validate(result)
            if validated:
                return validated

        # ── Step 5: Time-Based (strict 5x verify) ─────────────
        display.update_current(url, param, "ghauri", "time-based (5x)...")
        result = self._test_time_based(url, param, hdr, dbms, baseline)
        if result:
            validated = self.validator.validate(result)
            if validated:
                return validated

        display.mark_rejected()
        return None

    def _test_error_based(self, url, param, headers, dbms, baseline) -> dict | None:
        payloads = self.payload_brain.get_error_payloads(dbms, count=4)
        for payload in payloads:
            probe = self.payload_brain.inject_param(url, param, payload)
            resp  = self.fingerprinter.check_error_based(probe, headers)
            if not resp:
                continue
            analysis = self.error_brain.analyze_response(resp["body"], resp.get("status", 200))
            if analysis["action"] == "confirmed":
                return {
                    "url":        url,
                    "param":      param,
                    "type":       "Error-Based",
                    "engine":     "brain/sqlmap",
                    "dbms":       analysis.get("dbms", dbms),
                    "confidence": min(0.90 + analysis.get("confidence_add", 0), 0.99),
                    "payload":    payload,
                    "details":    resp["body"][:300],
                }
        return None

    def _test_boolean(self, url, param, headers, baseline) -> dict | None:
        pairs = self.payload_brain.get_boolean_pairs(count=2)
        for p_true, p_false in pairs:
            url_true  = self.payload_brain.inject_param(url, param, p_true)
            url_false = self.payload_brain.inject_param(url, param, p_false)

            check = self.fingerprinter.check_boolean_based(
                url_true, url_false, headers, baseline
            )
            if check.get("confirmed"):
                return {
                    "url":        url,
                    "param":      param,
                    "type":       "Boolean-Based Blind",
                    "engine":     "brain/sqlmap",
                    "dbms":       "Unknown",
                    "confidence": 0.82,
                    "payload":    f"TRUE:{p_true} | FALSE:{p_false}",
                    "details":    (f"Size true:{check['size_true']} "
                                   f"false:{check['size_false']} "
                                   f"diff:{check['size_diff_pct']}%"),
                }
        return None

    def _test_time_based(self, url, param, headers, dbms, baseline) -> dict | None:
        sleep_secs = 5
        payloads   = self.payload_brain.get_time_payloads(dbms, sleep_secs, count=2)

        for payload in payloads:
            probe_url = self.payload_brain.inject_param(url, param, payload)
            check     = self.fingerprinter.check_time_based(
                url, probe_url, headers,
                sleep_secs=sleep_secs,
                baseline=baseline,
                verify_count=5  # strict — 5 consistent delays required
            )
            if check.get("confirmed"):
                return {
                    "url":        url,
                    "param":      param,
                    "type":       "Time-Based Blind",
                    "engine":     "brain/ghauri",
                    "dbms":       dbms if dbms != "generic" else "Unknown",
                    "confidence": 0.86,
                    "payload":    payload,
                    "details":    (f"Avg delay:{check['avg_delay']}s "
                                   f"base:{check['base_avg']}s "
                                   f"stddev:{check['std_delay']}s"),
                    "time_check": check,
                }
        return None

    def _try_waf_bypass(self, url, param, headers, waf_analysis,
                        baseline, display) -> dict | None:
        """Try WAF bypass strategies before giving up."""
        strategy = waf_analysis.get("bypass_strategy", "comment_injection")
        payloads = self.error_brain.get_bypass_payloads(strategy)

        for payload in payloads[:3]:  # try top 3 bypass payloads
            probe = self.payload_brain.inject_param(url, param, payload)
            resp  = self.fingerprinter.check_error_based(probe, headers)
            if not resp:
                continue
            analysis = self.error_brain.analyze_response(resp["body"], resp.get("status", 200))
            if analysis["action"] == "confirmed":
                return {
                    "url":        url,
                    "param":      param,
                    "type":       "Error-Based (WAF Bypass)",
                    "engine":     "brain",
                    "dbms":       analysis.get("dbms", "Unknown"),
                    "confidence": 0.87,
                    "payload":    payload,
                    "waf":        waf_analysis.get("waf_detected", "Unknown"),
                    "details":    resp["body"][:300],
                }
        return None

    def _key(self, p):
        return f"{p.get('url','')}::{p.get('param','')}::{p.get('param_type','')}"

    def _save_checkpoint(self, p):
        self._done_keys.add(self._key(p))
        path = f"logs/checkpoint_{self.scan_id}.json"
        try:
            os.makedirs("logs", exist_ok=True)
            with open(path, "w") as f:
                json.dump(list(self._done_keys), f)
        except Exception:
            pass

    def _load_checkpoint(self):
        if not os.path.isdir("logs"):
            return
        files = sorted(f for f in os.listdir("logs") if f.startswith("checkpoint_"))
        if not files:
            return
        try:
            with open(f"logs/{files[-1]}") as f:
                self._done_keys = set(json.load(f))
            print(f"  \033[36m[resume] {len(self._done_keys)} already done\033[0m")
        except Exception:
            pass
