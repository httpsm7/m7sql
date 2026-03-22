"""m7sql.discovery.params — Injection Point Discovery v4"""
import json
from urllib.parse import urlparse, parse_qs

WORDLIST = ["id","user_id","uid","pid","search","q","query","filter",
            "category","name","username","email","token","key","sort",
            "order","offset","limit","file","path","include","action"]

INJ_HEADERS = ["X-Forwarded-For","X-Real-IP","X-Forwarded-Host","Client-IP"]


class ParamDiscovery:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def discover(self, endpoint):
        if not endpoint:
            return []
        if isinstance(endpoint, dict):
            return self._from_dict(endpoint)
        return self._from_url(endpoint)

    def _from_url(self, url):
        pts = []
        p   = urlparse(url)
        qs  = parse_qs(p.query, keep_blank_values=True)

        for param in qs:
            pts.append(self._pt(url, param, "GET"))

        # Wordlist only if no real params
        if not qs:
            base = f"{p.scheme}://{p.netloc}{p.path}"
            for w in WORDLIST[:10]:
                pts.append(self._pt(f"{base}?{w}=1", w, "GET", wordlist=True))

        # Headers only for API-like URLs
        if any(x in url for x in ("/api", "/v1", "/v2", "/rest", "/graphql")):
            for h in INJ_HEADERS[:3]:
                pts.append(self._pt(url, h, "HEADER"))

        return pts

    def _from_dict(self, t):
        pts     = []
        url     = t.get("url", "")
        method  = t.get("method", "GET").upper()
        data    = t.get("data", "")
        headers = t.get("headers", {})

        p  = urlparse(url)
        qs = parse_qs(p.query, keep_blank_values=True)
        for param in qs:
            pts.append(self._pt(url, param, "GET"))

        if method == "POST" and data:
            pts.extend(self._body(url, data, headers))

        # Headers only on API endpoints
        if any(x in url for x in ("/api", "/v1", "/v2")):
            for h in INJ_HEADERS[:2]:
                pts.append(self._pt(url, h, "HEADER"))

        cookie = headers.get("Cookie", "")
        if cookie:
            for part in cookie.split(";"):
                if "=" in part:
                    pts.append(self._pt(url, part.split("=")[0].strip(), "COOKIE"))
        return pts

    def _body(self, url, data, headers):
        pts = []
        ct  = headers.get("Content-Type", "").lower()
        if "json" in ct or (data.strip().startswith(("{", "["))):
            try:
                obj = json.loads(data)
                for key in self._flatten(obj):
                    pts.append(self._pt(url, key, "JSON", data=data))
            except Exception:
                pass
        else:
            try:
                from urllib.parse import parse_qs as pqs
                for param in pqs(data, keep_blank_values=True):
                    pts.append(self._pt(url, param, "POST", data=data))
            except Exception:
                pass
        return pts

    def _flatten(self, obj, prefix=""):
        keys = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                full = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    keys.extend(self._flatten(v, full))
                else:
                    keys.append(full)
        elif isinstance(obj, list) and obj:
            keys.extend(self._flatten(obj[0], f"{prefix}[0]"))
        return keys

    @staticmethod
    def _pt(url, param, ptype, data=None, wordlist=False):
        return {"url": url, "param": param, "param_type": ptype,
                "data": data, "is_wordlist": wordlist, "headers": {}}
