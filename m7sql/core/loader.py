"""m7sql.core.loader — Target Loader v4"""
import re
from urllib.parse import urlparse, urlunparse


class TargetLoader:
    def __init__(self, scope=None, verbose=False):
        self.scope   = scope
        self.verbose = verbose

    def from_url(self, url):
        url = self._normalize(url)
        return [{"url": url, "method": "GET", "headers": {}, "data": None}] if url else []

    def from_file(self, filepath):
        targets, seen = [], set()
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                url = self._normalize(line)
                if url and url not in seen:
                    seen.add(url)
                    targets.append({"url": url, "method": "GET", "headers": {}, "data": None})
        return targets

    def from_raw(self, filepath):
        with open(filepath, encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        return [self._parse_raw(raw)]

    def _normalize(self, url):
        url = url.strip()
        if not url:
            return None
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        try:
            p = urlparse(url)
        except Exception:
            return None
        if not p.netloc:
            return None
        host      = p.hostname or ""
        is_ip     = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))
        is_local  = host in ("localhost", "127.0.0.1", "::1")
        has_tld   = "." in host
        if not (is_ip or is_local or has_tld):
            return None
        if self.scope and self.scope not in p.netloc:
            return None
        return urlunparse((p.scheme, p.netloc, p.path or "/", p.params, p.query, ""))

    def _parse_raw(self, raw):
        lines  = raw.replace("\r\n", "\n").split("\n")
        req    = lines[0].strip().split()
        method = req[0] if req else "GET"
        path   = req[1] if len(req) > 1 else "/"
        headers, host, body_start = {}, "", 0
        for i, line in enumerate(lines[1:], 1):
            if not line.strip():
                body_start = i + 1
                break
            if ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip()] = v.strip()
                if k.strip().lower() == "host":
                    host = v.strip()
        body = "\n".join(lines[body_start:]).strip() if body_start else None
        url  = self._normalize(f"https://{host}{path}")
        return {"url": url, "method": method.upper(), "headers": headers, "data": body}
