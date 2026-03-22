"""
m7sql.brain.display — Live Terminal Display Engine
Real-time dashboard showing exactly what's happening.
Instant vuln alert when something is found.
"""

import threading
import time
import sys
import os


R    = '\033[31m'
G    = '\033[32m'
Y    = '\033[33m'
C    = '\033[36m'
B    = '\033[90m'
W    = '\033[0m'
BOLD = '\033[1m'
MAG  = '\033[35m'


class LiveDisplay:

    def __init__(self, total_points: int, total_urls: int, skipped: int):
        self.total_points = total_points
        self.total_urls   = total_urls
        self.skipped      = skipped

        self._lock      = threading.Lock()
        self._scanned   = 0
        self._vulns     = 0
        self._rejected  = 0
        self._current   = ""
        self._current_p = ""
        self._current_e = ""
        self._current_s = ""
        self._findings  = []
        self._start     = time.time()

    def update_current(self, url: str, param: str, engine: str, status: str):
        """Update what's being tested right now."""
        with self._lock:
            self._current   = url[:65] if len(url) > 65 else url
            self._current_p = param
            self._current_e = engine
            self._current_s = status
        self._render()

    def mark_scanned(self):
        with self._lock:
            self._scanned += 1
        self._render()

    def mark_rejected(self):
        with self._lock:
            self._rejected += 1

    def found_vuln(self, result: dict):
        """Called immediately when a real vulnerability is confirmed."""
        with self._lock:
            self._vulns += 1
            self._findings.append(result)

        # Print instant alert (breaks dashboard flow intentionally)
        url    = result.get("url", "")[:70]
        param  = result.get("param", "")
        typ    = result.get("type", "SQLi")
        sev    = result.get("severity", "High")
        engine = result.get("engine", "")
        dbms   = result.get("dbms", "")
        conf   = result.get("confidence", 0)

        sev_color = R if sev in ("Critical", "High") else Y

        print(f"\n\n{sev_color}{BOLD}{'▓'*60}{W}")
        print(f"{sev_color}{BOLD}  ⚡ VULNERABILITY FOUND!{W}")
        print(f"{sev_color}{BOLD}{'▓'*60}{W}")
        print(f"  {C}URL    {W}: {url}")
        print(f"  {C}Param  {W}: {BOLD}{param}{W}")
        print(f"  {C}Type   {W}: {sev_color}{BOLD}{typ}{W}")
        print(f"  {C}Engine {W}: {engine}")
        print(f"  {C}DBMS   {W}: {dbms if dbms else 'Detecting...'}")
        print(f"  {C}Sev    {W}: {sev_color}{BOLD}{sev}{W}")
        print(f"  {C}Conf   {W}: {conf}")
        print(f"{sev_color}{BOLD}{'▓'*60}{W}\n")

    def _render(self):
        """Render the live dashboard line."""
        with self._lock:
            sc  = self._scanned
            vl  = self._vulns
            rj  = self._rejected
            cur = self._current
            prm = self._current_p
            eng = self._current_e
            sts = self._current_s
            tot = self.total_points
            ela = time.time() - self._start

        filled = int(28 * sc / tot) if tot else 0
        bar    = G + "█" * filled + B + "░" * (28 - filled) + W
        pct    = int(sc / tot * 100) if tot else 0

        vc = R if vl else G
        elapsed_str = f"{int(ela//60)}m{int(ela%60)}s"

        # Main progress line
        line1 = (
            f"\r  [{bar}] {C}{pct}%{W} "
            f"{B}({sc}/{tot}){W} | "
            f"{vc}⚡{vl} vuln{W} | "
            f"{B}✗{rj} skip{W} | "
            f"{B}{elapsed_str}{W}"
        )

        # Current target line
        line2 = (
            f"\n  {B}▶{W} {C}{cur[:50]}{W}"
            f"{B}?{prm}{W}"
            f"  {MAG}[{eng}]{W}"
            f"  {B}{sts}{W}"
            f"\033[A"  # move cursor back up
        )

        print(line1 + line2, end="", flush=True)

    def finish(self):
        """Print final summary."""
        with self._lock:
            sc  = self._scanned
            vl  = self._vulns
            rj  = self._rejected
            ela = time.time() - self._start
            sk  = self.skipped

        print("\n")
        print(f"{B}{'═'*60}{W}")
        print(f"{G}{BOLD}  SCAN COMPLETE{W}")
        print(f"{B}{'═'*60}{W}")
        print(f"  {C}Total URLs    {W}: {self.total_urls}")
        print(f"  {C}Skipped (FP)  {W}: {B}{sk}{W}")
        print(f"  {C}Points tested {W}: {sc}")
        print(f"  {C}Rejected (FP) {W}: {B}{rj}{W}")
        print(f"  {C}VULNERABLE    {W}: {R if vl else G}{BOLD}{vl}{W}")
        print(f"  {C}Duration      {W}: {int(ela//60)}m {int(ela%60)}s")
        print(f"{B}{'═'*60}{W}")

        if self._findings:
            print(f"\n{R}{BOLD}  CONFIRMED FINDINGS:{W}")
            for i, f in enumerate(self._findings, 1):
                sev = f.get("severity","High")
                sc  = R if sev in ("Critical","High") else Y
                print(f"  {sc}{i}. [{sev}]{W} {f.get('param','')} "
                      f"→ {f.get('type','')} @ {f.get('url','')[:55]}")
        print()
