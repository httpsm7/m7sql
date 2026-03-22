"""m7sql.core.session — Session & Auth Manager v4"""
import json, urllib.request, urllib.parse


class SessionManager:
    def __init__(self, login_config=None, cookie=None, headers=None, proxy=None):
        self._cookies = {}
        self._tokens  = {}
        self._headers = headers or {}

        if cookie:
            for part in cookie.split(";"):
                part = part.strip()
                if "=" in part:
                    k, _, v = part.partition("=")
                    self._cookies[k.strip()] = v.strip()

        if login_config:
            self._login(login_config)

    def get_headers(self):
        h = dict(self._headers)
        if self._cookies:
            cs = "; ".join(f"{k}={v}" for k, v in self._cookies.items())
            h["Cookie"] = (h.get("Cookie", "") + "; " + cs).lstrip("; ")
        if "Authorization" not in h and "token" in self._tokens:
            h["Authorization"] = f"Bearer {self._tokens['token']}"
        return h

    def _login(self, config_path):
        try:
            with open(config_path) as f:
                cfg = json.load(f)
            url  = cfg.get("url", "")
            meth = cfg.get("method", "POST").upper()
            data = cfg.get("data", {})
            ct   = cfg.get("content_type", "application/x-www-form-urlencoded")
            body = (json.dumps(data).encode() if "json" in ct
                    else urllib.parse.urlencode(data).encode())
            req  = urllib.request.Request(url, data=body, method=meth)
            req.add_header("Content-Type", ct)
            req.add_header("User-Agent", "m7sql/4.0")
            with urllib.request.urlopen(req, timeout=15) as r:
                sc = r.getheader("Set-Cookie", "")
                if sc:
                    first = sc.split(";")[0].strip()
                    if "=" in first:
                        k, _, v = first.partition("=")
                        self._cookies[k.strip()] = v.strip()
                try:
                    jr = json.loads(r.read().decode("utf-8", "ignore"))
                    tf = cfg.get("token_field", "access_token")
                    if tf in jr:
                        self._tokens["token"] = jr[tf]
                except Exception:
                    pass
            print(f"  \033[32m[auth] Session OK: {url}\033[0m")
        except Exception as e:
            print(f"  \033[33m[auth] Login failed: {e}\033[0m")
