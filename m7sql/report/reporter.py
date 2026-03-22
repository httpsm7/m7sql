"""m7sql.report — Formatter + Exporter v4"""
import os, json, csv


class ReportFormatter:
    def __init__(self, scan_id, start_time, end_time, duration, targets_count, args):
        self.scan_id       = scan_id
        self.start_time    = start_time
        self.end_time      = end_time
        self.duration      = duration
        self.targets_count = targets_count
        self.args          = args

    def build(self, results):
        vuln = [r for r in results if r.get("confidence", 0) >= 0.70]
        low  = [r for r in results if 0.5 <= r.get("confidence", 0) < 0.70]
        return {
            "meta": {
                "tool": "m7sql", "version": "4.0",
                "author": "Sharlix / Milkyway Intelligence",
                "scan_id": self.scan_id,
                "start_time": self.start_time.isoformat(),
                "end_time":   self.end_time.isoformat(),
                "duration_seconds": round(self.duration, 2),
                "disclaimer": "ONLY for authorized security testing, research, educational purposes.",
            },
            "scan_config": {
                "mode": self.args.mode, "threads": self.args.threads,
                "auto_exploit": self.args.auto == "on",
                "proxy": self.args.proxy, "scope": self.args.scope,
            },
            "summary": {
                "total_targets": self.targets_count,
                "vulnerable":    len(vuln),
                "low_confidence":len(low),
                "critical": len([r for r in vuln if r.get("severity") == "Critical"]),
                "high":     len([r for r in vuln if r.get("severity") == "High"]),
                "medium":   len([r for r in vuln if r.get("severity") == "Medium"]),
            },
            "findings":      self._fmt(vuln),
            "low_confidence":self._fmt(low),
        }

    def _fmt(self, items):
        return [{
            "url":           r.get("url", ""),
            "param":         r.get("param", ""),
            "type":          r.get("type", "SQLi"),
            "engine":        r.get("engine", ""),
            "dbms":          r.get("dbms", "Unknown"),
            "severity":      r.get("severity", "Unknown"),
            "confidence":    r.get("confidence", 0),
            "payload":       r.get("payload"),
            "current_db":    r.get("current_db"),
            "tables":        r.get("tables"),
            "waf":           r.get("waf"),
            "details":       r.get("details", "")[:250],
        } for r in items]


SEV_COLOR = {"Critical": "#ff2222", "High": "#ff6600", "Medium": "#ffaa00", "Low": "#33cc66"}


class ReportExporter:
    def __init__(self, output_dir, scan_id):
        self.dir     = output_dir
        self.scan_id = scan_id
        os.makedirs(output_dir, exist_ok=True)

    def to_json(self, report):
        p = self._path("json")
        with open(p, "w") as f:
            json.dump(report, f, indent=2)
        return p

    def to_csv(self, report):
        p      = self._path("csv")
        rows   = report.get("findings", []) + report.get("low_confidence", [])
        fields = ["url", "param", "type", "engine", "dbms",
                  "severity", "confidence", "payload", "current_db", "tables"]
        with open(p, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
            w.writeheader()
            for r in rows:
                row = dict(r)
                if isinstance(row.get("tables"), list):
                    row["tables"] = ", ".join(row["tables"])
                w.writerow(row)
        return p

    def to_html(self, report):
        p = self._path("html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(self._build_html(report))
        return p

    def _path(self, ext):
        return os.path.join(self.dir, f"m7sql_{self.scan_id}.{ext}")

    def _build_html(self, report):
        meta    = report.get("meta", {})
        summary = report.get("summary", {})
        cfg     = report.get("scan_config", {})
        finds   = report.get("findings", [])

        rows = ""
        for f in finds:
            sev   = f.get("severity", "Unknown")
            color = SEV_COLOR.get(sev, "#888")
            tbls  = ", ".join(f.get("tables") or []) or "—"
            waf   = f.get("waf", "—") or "—"
            pay   = (f.get("payload") or "")[:60]
            rows += f"""
            <tr>
              <td class="url" title="{f.get('url','')}">{f.get('url','')[:55]}</td>
              <td><b>{f.get('param','')}</b></td>
              <td>{f.get('type','')}</td>
              <td>{f.get('engine','')}</td>
              <td>{f.get('dbms','')}</td>
              <td style="color:{color};font-weight:700">{sev}</td>
              <td>{f.get('confidence','')}</td>
              <td class="code">{pay}</td>
              <td>{waf}</td>
              <td>{tbls}</td>
            </tr>"""

        if not rows:
            rows = '<tr><td colspan="10" style="text-align:center;color:#555;padding:30px">No confirmed vulnerabilities</td></tr>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8">
<title>m7sql v4.0 Report — {meta.get('scan_id','')}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#080810;color:#ccc;font-family:'Courier New',monospace;font-size:12px}}
header{{background:#0d0d18;border-bottom:2px solid #00ff41;padding:16px 32px}}
header h1{{color:#00ff41;font-size:22px;letter-spacing:4px}}
header p{{color:#444;font-size:10px;margin-top:3px}}
.wrap{{max-width:1500px;margin:0 auto;padding:24px 32px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:12px;margin-bottom:24px}}
.card{{background:#111;border:1px solid #1a1a1a;border-radius:8px;padding:12px;text-align:center}}
.card .n{{font-size:28px;font-weight:700}}
.card .l{{font-size:9px;color:#444;margin-top:4px;text-transform:uppercase;letter-spacing:1px}}
.c-g .n{{color:#00ff41}}.c-r .n{{color:#ff2222}}.c-o .n{{color:#ff6600}}
.c-y .n{{color:#ffaa00}}.c-b .n{{color:#888}}
.meta{{background:#111;border:1px solid #1a1a1a;border-radius:6px;padding:14px;
       margin-bottom:20px;font-size:10px;color:#444;line-height:1.9}}
.meta b{{color:#00ff41}}
table{{width:100%;border-collapse:collapse;margin-bottom:20px;font-size:11px}}
th{{background:#131320;color:#00ff41;padding:9px 8px;text-align:left;
    border:1px solid #1a1a1a;font-size:9px;letter-spacing:1px}}
td{{padding:7px 8px;border:1px solid #131320;vertical-align:top}}
tr:hover td{{background:#0f0f1c}}
.url{{max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#4af}}
.code{{font-family:monospace;color:#fa0;font-size:10px;max-width:200px;
       overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
h2{{color:#00ff41;font-size:11px;letter-spacing:3px;text-transform:uppercase;
    border-bottom:1px solid #1a1a1a;padding-bottom:7px;margin-bottom:14px}}
.disc{{background:#150000;border:1px solid #2a0000;border-radius:6px;
       padding:10px 14px;color:#ff4444;font-size:10px;margin-top:14px}}
</style></head>
<body>
<header>
  <h1>⬡ M7SQL v4.0 — Brain Edition</h1>
  <p>Milkyway Intelligence · Sharlix · Scan: {meta.get('scan_id','')} · Duration: {meta.get('duration_seconds','')}s</p>
</header>
<div class="wrap">
  <div class="cards">
    <div class="card c-g"><div class="n">{summary.get('total_targets',0)}</div><div class="l">Targets</div></div>
    <div class="card c-r"><div class="n">{summary.get('vulnerable',0)}</div><div class="l">Vulnerable</div></div>
    <div class="card c-r"><div class="n">{summary.get('critical',0)}</div><div class="l">Critical</div></div>
    <div class="card c-o"><div class="n">{summary.get('high',0)}</div><div class="l">High</div></div>
    <div class="card c-y"><div class="n">{summary.get('medium',0)}</div><div class="l">Medium</div></div>
    <div class="card c-b"><div class="n">{meta.get('duration_seconds','—')}s</div><div class="l">Duration</div></div>
  </div>
  <div class="meta">
    <b>Scan:</b> {meta.get('start_time','')} → {meta.get('end_time','')}&nbsp;&nbsp;
    <b>Mode:</b> {cfg.get('mode','')} &nbsp;
    <b>Threads:</b> {cfg.get('threads','')} &nbsp;
    <b>Auto-Exploit:</b> {cfg.get('auto_exploit',False)}
  </div>
  <h2>Confirmed Findings ({len(finds)})</h2>
  <table>
    <thead><tr>
      <th>URL</th><th>PARAM</th><th>TYPE</th><th>ENGINE</th><th>DBMS</th>
      <th>SEV</th><th>CONF</th><th>PAYLOAD</th><th>WAF</th><th>TABLES</th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="disc">⚠ LEGAL: {meta.get('disclaimer','')}</div>
</div></body></html>"""
