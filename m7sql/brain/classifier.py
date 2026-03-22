"""
m7sql.brain.classifier — Target Classifier
Decides which URLs are worth testing and which to skip.
Kills false positives BEFORE scanning even starts.
"""

import re
from urllib.parse import urlparse, parse_qs


# ── Static/useless patterns — skip immediately ────────────────
SKIP_EXTENSIONS = {
    '.xml', '.txt', '.pdf', '.png', '.jpg', '.jpeg', '.gif',
    '.svg', '.ico', '.css', '.js', '.woff', '.woff2', '.ttf',
    '.eot', '.mp4', '.mp3', '.zip', '.tar', '.gz', '.map',
    '.webp', '.avif', '.bmp', '.tiff', '.doc', '.docx', '.xls',
}

SKIP_PATH_PATTERNS = [
    r'/sitemap', r'/robots\.txt', r'/health', r'/ping', r'/status',
    r'/heartbeat', r'/favicon', r'/static/', r'/assets/', r'/dist/',
    r'/build/', r'/vendor/', r'/node_modules/', r'/_next/', r'/__',
    r'/newsletter', r'/subscribe', r'/unsubscribe', r'/rss',
    r'/feed', r'/atom', r'/manifest', r'/sw\.js', r'/service-worker',
    r'/cdn-cgi/', r'/wp-content/plugins', r'/wp-includes/',
    r'/images/', r'/fonts/', r'/media/', r'/uploads/', r'/files/',
    r'\.well-known',
]

SKIP_PARAM_PATTERNS = [
    # Analytics / tracking
    r'^utm_', r'^_ga', r'^fbclid$', r'^gclid$', r'^msclkid$',
    r'^_branch', r'^campaign_', r'^ad_', r'^adgroup', r'^creative',
    r'^placement', r'^network', r'^device', r'^matchtype',
    r'^keyword', r'^ref$', r'^source$', r'^medium$',
    # Non-injectable
    r'^format$', r'^lang$', r'^locale$', r'^currency$',
    r'^timezone$', r'^_csrf', r'^csrf', r'^__', r'^nonce$',
]

# ── High-value dynamic indicators ─────────────────────────────
HIGH_VALUE_PARAMS = {
    'id', 'user_id', 'userid', 'uid', 'pid', 'account_id',
    'product_id', 'item_id', 'order_id', 'customer_id',
    'search', 'q', 'query', 'keyword', 'filter', 'category',
    'username', 'email', 'token', 'key', 'name', 'title',
    'description', 'content', 'message', 'comment', 'body',
    'page', 'offset', 'limit', 'sort', 'order', 'type',
    'file', 'path', 'dir', 'include', 'template', 'view',
    'action', 'method', 'cmd', 'exec', 'code', 'data',
}

API_INDICATORS = [
    r'/api/', r'/v\d+/', r'/graphql', r'/rest/', r'/json',
    r'/ajax/', r'/service/', r'/endpoint', r'/rpc',
]

DYNAMIC_PATH = re.compile(
    r'/\d+(/|$)|'           # /users/123
    r'/[a-f0-9]{8,}(/|$)|' # /abc12345ef
    r'/[a-f0-9\-]{36}(/|$)' # UUID
)


class TargetClassifier:

    def __init__(self):
        self._skip_path_re  = re.compile('|'.join(SKIP_PATH_PATTERNS), re.I)
        self._skip_param_re = re.compile('|'.join(SKIP_PARAM_PATTERNS), re.I)
        self._api_re        = re.compile('|'.join(API_INDICATORS), re.I)

    def classify_url(self, url: str) -> dict:
        """
        Returns:
            {
                "action": "test" | "skip",
                "reason": str,
                "priority": 0-10,
                "url_type": "api" | "web" | "static",
            }
        """
        try:
            parsed = urlparse(url)
        except Exception:
            return self._skip("invalid URL")

        path   = parsed.path.lower()
        query  = parsed.query
        params = parse_qs(query, keep_blank_values=True)

        # ── Extension check ───────────────────────────────────
        ext = '.' + path.split('.')[-1] if '.' in path.split('/')[-1] else ''
        if ext in SKIP_EXTENSIONS:
            return self._skip(f"static file ({ext})")

        # ── Path pattern check ────────────────────────────────
        if self._skip_path_re.search(path):
            return self._skip("static/non-injectable path")

        # ── No params at all ──────────────────────────────────
        if not params:
            # Maybe API with dynamic path
            if DYNAMIC_PATH.search(path) or self._api_re.search(path):
                return self._test("dynamic path — possible REST param", 6, "api")
            return self._skip("no parameters found")

        # ── All params are tracking/analytics ─────────────────
        real_params = [
            p for p in params
            if not self._skip_param_re.search(p)
        ]
        if not real_params:
            return self._skip("only tracking/analytics params")

        # ── Calculate priority ────────────────────────────────
        priority   = 0
        url_type   = "web"

        # API bonus
        if self._api_re.search(url):
            priority += 3
            url_type  = "api"

        # Dynamic path bonus
        if DYNAMIC_PATH.search(path):
            priority += 2

        # High value param bonus
        hv_count = sum(1 for p in real_params if p.lower() in HIGH_VALUE_PARAMS)
        priority += hv_count * 2

        # Numeric value params (id=1, pid=42) — very injectable
        for p in real_params:
            vals = params.get(p, [''])
            if vals and vals[0].isdigit():
                priority += 2
                break

        priority = min(priority, 10)

        return self._test(
            f"{len(real_params)} real param(s): {', '.join(real_params[:3])}",
            priority,
            url_type
        )

    def classify_param(self, param: str, url: str) -> dict:
        """Classify a single injection point."""
        param_l = param.lower()

        # Skip tracking params
        if self._skip_param_re.search(param_l):
            return {"action": "skip", "reason": f"tracking param: {param}"}

        # Skip header injection on non-API, non-dynamic URLs
        if param in ('X-Forwarded-For', 'X-Real-IP', 'X-Forwarded-Host',
                     'Client-IP', 'True-Client-IP'):
            parsed = urlparse(url)
            path   = parsed.path.lower()
            # Only test headers on API endpoints, not static/blog pages
            if not self._api_re.search(url) and not DYNAMIC_PATH.search(path):
                return {"action": "skip", "reason": "header inject on non-API URL"}

        score = 0
        if param_l in HIGH_VALUE_PARAMS:          score += 5
        if any(k in param_l for k in ('id','key','token','pass','user','name')):
            score += 3
        if self._api_re.search(url):              score += 2

        return {"action": "test", "score": score}

    @staticmethod
    def _skip(reason: str) -> dict:
        return {"action": "skip", "reason": reason, "priority": 0, "url_type": "static"}

    @staticmethod
    def _test(reason: str, priority: int, url_type: str) -> dict:
        return {"action": "test", "reason": reason, "priority": priority, "url_type": url_type}
