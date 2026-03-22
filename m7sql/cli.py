#!/usr/bin/env python3
"""
m7sql v4.0 Brain Edition — Milkyway Intelligence
Fully Automated SQLi Testing Framework with Smart Brain
Author : Sharlix | github.com/httpsm7
Legal  : Authorized testing only — Stay ethical.
"""

import argparse
import sys
import os
import json
from datetime import datetime

from m7sql.core.loader    import TargetLoader
from m7sql.core.session   import SessionManager
from m7sql.core.scanner   import SmartScanner
from m7sql.discovery.params import ParamDiscovery
from m7sql.exploit.controller import ExploitController
from m7sql.report.reporter import ReportFormatter, ReportExporter

R='\033[31m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'
B='\033[90m'; W='\033[0m'; BOLD='\033[1m'; MAG='\033[35m'

BANNER = f"""
{G}
 ███╗   ███╗███████╗███████╗ ██████╗ ██╗     {MAG} ██████╗ ██████╗  █████╗ ██╗███╗  ██╗{W}
{G} ████╗ ████║╚════██║██╔════╝██╔═══██╗██║     {MAG}██╔══██╗██╔══██╗██╔══██╗██║████╗ ██║{W}
{G} ██╔████╔██║    ██╔╝███████╗██║   ██║██║     {MAG}██████╔╝██████╔╝███████║██║██╔██╗██║{W}
{G} ██║╚██╔╝██║   ██╔╝ ╚════██║██║▄▄ ██║██║     {MAG}██╔══██╗██╔══██╗██╔══██║██║██║╚████║{W}
{G} ██║ ╚═╝ ██║   ██║  ███████║╚██████╔╝███████╗{MAG}██████╔╝██║  ██║██║  ██║██║██║ ╚███║{W}
{G} ╚═╝     ╚═╝   ╚═╝  ╚══════╝ ╚══▀▀═╝ ╚══════╝{MAG}╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚══╝{W}

{B} v4.0 Brain Edition | Milkyway Intelligence | github.com/httpsm7{W}
{R} ⚠  Authorized testing only. You are responsible for your actions.{W}
"""


def parse_args():
    p = argparse.ArgumentParser(
        prog="m7sql",
        description="m7sql v4.0 Brain Edition — Smart SQLi Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  m7sql -u "http://testphp.vulnweb.com/listproducts.php?cat=1"
  m7sql -f urls.txt --threads 10 --auto on --output all
  m7sql --raw request.txt --proxy http://127.0.0.1:8080
  m7sql -f urls.txt --scope etsy.com --output html
        """
    )

    inp = p.add_argument_group("📥 Input")
    inp.add_argument("-u", "--url",  metavar="URL",  help="Single target URL")
    inp.add_argument("-f", "--file", metavar="FILE", help="File with URLs")
    inp.add_argument("--raw",        metavar="FILE", help="Raw Burp HTTP request")

    ctl = p.add_argument_group("⚙️  Control")
    ctl.add_argument("--auto", choices=["on","off"], default="on",
                     help="Auto exploit DB enum (default: ON)")
    ctl.add_argument("--mode", choices=["fast","balanced","deep"], default="balanced",
                     help="Scan mode (default: balanced)")

    perf = p.add_argument_group("🚀 Performance")
    perf.add_argument("--threads", type=int, default=8,   metavar="N")
    perf.add_argument("--timeout", type=int, default=20,  metavar="SEC")
    perf.add_argument("--retries", type=int, default=2,   metavar="N")

    net = p.add_argument_group("🌐 Network")
    net.add_argument("--proxy",   metavar="URL")
    net.add_argument("--headers", metavar="JSON")
    net.add_argument("--cookie",  metavar="STRING")
    net.add_argument("--scope",   metavar="DOMAIN")

    auth = p.add_argument_group("🔐 Auth")
    auth.add_argument("--login-config", metavar="FILE")

    out = p.add_argument_group("📄 Output")
    out.add_argument("--output",     choices=["json","csv","html","all"], default="all")
    out.add_argument("--output-dir", metavar="DIR", default="./m7sql_reports")
    out.add_argument("--resume",     action="store_true")
    out.add_argument("-v","--verbose", action="store_true")
    out.add_argument("-q","--quiet",   action="store_true")

    return p.parse_args()


def validate(args):
    if not any([args.url, args.file, args.raw]):
        print(f"{R}[ERROR]{W} Provide: -u URL  or  -f FILE  or  --raw FILE")
        sys.exit(1)
    for attr, label in [("file","--file"), ("raw","--raw"), ("login_config","--login-config")]:
        val = getattr(args, attr, None)
        if val and not os.path.isfile(val):
            print(f"{R}[ERROR]{W} {label} not found: {val}")
            sys.exit(1)


def main():
    args = parse_args()

    if not args.quiet:
        print(BANNER)

    validate(args)

    # Inject scan_id into args (needed by scanner for checkpoint)
    start_time    = datetime.now()
    args.scan_id  = start_time.strftime("%Y%m%d_%H%M%S")

    os.makedirs(args.output_dir, exist_ok=True)
    os.makedirs("logs", exist_ok=True)

    custom_headers = {}
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
        except Exception:
            print(f"{Y}[WARN]{W} Invalid --headers JSON")

    print(f"{B}{'─'*58}{W}")
    print(f"  {C}Mode{W}     : {args.mode}  |  {C}Threads{W}: {args.threads}  |  {C}Timeout{W}: {args.timeout}s")
    print(f"  {C}Auto{W}     : {'ON ⚡' if args.auto=='on' else 'OFF'}")
    print(f"  {C}Output{W}   : {args.output} → {args.output_dir}")
    if args.proxy:  print(f"  {C}Proxy{W}    : {args.proxy}")
    if args.scope:  print(f"  {C}Scope{W}    : {args.scope}")
    print(f"{B}{'─'*58}{W}\n")

    # ── 1. Load ───────────────────────────────────────────────
    print(f"{C}[1/5]{W} Loading targets...")
    loader  = TargetLoader(scope=args.scope, verbose=args.verbose)
    targets = (loader.from_url(args.url)   if args.url  else
               loader.from_file(args.file) if args.file else
               loader.from_raw(args.raw))

    if not targets:
        print(f"{R}[ERROR]{W} No valid targets.")
        sys.exit(1)
    print(f"{G}      ✓ {len(targets)} target(s){W}\n")

    # ── 2. Session ────────────────────────────────────────────
    print(f"{C}[2/5]{W} Session setup...")
    session = SessionManager(
        login_config=args.login_config,
        cookie=args.cookie,
        headers=custom_headers,
        proxy=args.proxy
    )
    print(f"{G}      ✓ Ready{W}\n")

    # ── 3. Param Discovery ────────────────────────────────────
    print(f"{C}[3/5]{W} Discovering injection points...")
    disc   = ParamDiscovery(verbose=args.verbose)
    points = []
    for t in targets:
        pts = disc.discover(t)
        points.extend(pts)
    print(f"{G}      ✓ {len(points)} raw point(s) found{W}\n")

    # ── 4. Brain Scan ─────────────────────────────────────────
    print(f"{C}[4/5]{W} Brain scanning...\n")
    scanner = SmartScanner(args=args, session=session)
    results = scanner.run(points)

    # ── Auto Exploit ──────────────────────────────────────────
    if args.auto == "on" and results:
        print(f"\n{Y}[!]{W} Auto-exploit running...")
        ctrl    = ExploitController(proxy=args.proxy, timeout=args.timeout, verbose=args.verbose)
        results = ctrl.run(results)

    # ── 5. Reports ────────────────────────────────────────────
    print(f"\n{C}[5/5]{W} Generating reports...")
    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    fmt    = ReportFormatter(args.scan_id, start_time, end_time,
                             duration, len(targets), args)
    report = fmt.build(results)
    exp    = ReportExporter(output_dir=args.output_dir, scan_id=args.scan_id)

    paths = []
    if args.output in ("json","all"): paths.append(("JSON", exp.to_json(report)))
    if args.output in ("csv", "all"): paths.append(("CSV",  exp.to_csv(report)))
    if args.output in ("html","all"): paths.append(("HTML", exp.to_html(report)))

    for name, path in paths:
        print(f"{G}      ✓ {name}: {path}{W}")


if __name__ == "__main__":
    main()
