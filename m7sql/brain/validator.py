"""
m7sql.brain.validator — Confidence Validator
Applies strict rules before anything gets reported.
Auto-reject rules kill false positives at final stage.
"""

import re
import hashlib
from urllib.parse import urlparse


# ── Auto-reject rules — these = definitely FP ────────────────
AUTO_REJECT_RULES = [
    # Time-based without DBMS confirmation
    {
        "condition": lambda r: (
            "time" in r.get("type","").lower() and
            r.get("dbms","") in ("", "Unknown") and
            r.get("confidence", 0) < 0.85
        ),
        "reason": "Time-based without DBMS — likely network latency",
    },
    # Header injection on non-API endpoints
    {
        "condition": lambda r: (
            r.get("param","") in (
                "X-Forwarded-For","X-Real-IP","X-Forwarded-Host",
                "Client-IP","True-Client-IP"
            ) and
            not any(x in r.get("url","") for x in ("/api", "/v1", "/v2", "/rest"))
        ),
        "reason": "Header injection on non-API endpoint",
    },
    # Redirect responses
    {
        "condition": lambda r: r.get("status_code", 200) in (301, 302, 303, 307, 308),
        "reason": "Redirect response — not injectable",
    },
    # Marketing/tracking URLs
    {
        "condition": lambda r: any(
            kw in r.get("url","").lower()
            for kw in ("utm_", "campaign_label", "_branch_match", "fbclid",
                       "gclid", "msclkid", "ref=", "adhoc")
        ),
        "reason": "Marketing/tracking URL",
    },
    # Static file paths
    {
        "condition": lambda r: any(
            r.get("url","").lower().endswith(ext)
            for ext in (".xml", ".txt", ".jpg", ".png", ".pdf",
                        ".css", ".js", ".woff", ".map")
        ),
        "reason": "Static file — not injectable",
    },
    # Sitemap paths
    {
        "condition": lambda r: "sitemap" in r.get("url","").lower(),
        "reason": "Sitemap URL",
    },
    # Low confidence below minimum
    {
        "condition": lambda r: r.get("confidence", 0) < 0.70,
        "reason": "Confidence below threshold (0.70)",
    },
    # Duplicate (same url + param + type)
]

# ── Minimum confidence thresholds ─────────────────────────────
MIN_CONFIDENCE = {
    "UNION-Based":         0.88,
    "Error-Based":         0.82,
    "Boolean-Based Blind": 0.78,
    "Time-Based Blind":    0.85,  # strict — lots of FP here
    "Stacked Queries":     0.88,
    "NoSQL Injection":     0.75,
    "default":             0.75,
}

# ── Verify count requirements ──────────────────────────────────
VERIFY_COUNT = {
    "UNION-Based":         2,
    "Error-Based":         2,
    "Boolean-Based Blind": 3,
    "Time-Based Blind":    5,  # must be consistent 5 times
    "Stacked Queries":     2,
    "NoSQL Injection":     2,
    "default":             2,
}


class ConfidenceValidator:

    def __init__(self):
        self._seen = set()

    def validate(self, result: dict) -> dict | None:
        """
        Apply all validation rules.
        Returns cleaned result or None if rejected.
        """
        if not result:
            return None

        # ── Deduplication ─────────────────────────────────────
        key = hashlib.md5(
            f"{result.get('url','')}::{result.get('param','')}::{result.get('type','')}".encode()
        ).hexdigest()
        if key in self._seen:
            return None
        self._seen.add(key)

        # ── Auto-reject rules ─────────────────────────────────
        for rule in AUTO_REJECT_RULES:
            try:
                if rule["condition"](result):
                    if result.get("verbose"):
                        print(f"  [validator] REJECTED: {rule['reason']}")
                    return None
            except Exception:
                pass

        # ── Type-specific minimum confidence ──────────────────
        sqli_type    = result.get("type", "default")
        min_conf     = MIN_CONFIDENCE.get(sqli_type, MIN_CONFIDENCE["default"])
        current_conf = result.get("confidence", 0)

        if current_conf < min_conf:
            return None

        # ── Assign final severity ─────────────────────────────
        result["severity"] = self._severity(sqli_type, current_conf)

        # ── Clean result ──────────────────────────────────────
        result["confidence"] = round(current_conf, 2)
        result.pop("verbose", None)
        result.pop("status_code", None)

        return result

    def required_verifications(self, sqli_type: str) -> int:
        return VERIFY_COUNT.get(sqli_type, VERIFY_COUNT["default"])

    @staticmethod
    def _severity(sqli_type: str, confidence: float) -> str:
        t = sqli_type.lower()
        if "union" in t or "stacked" in t:
            return "Critical"
        if "error" in t:
            return "High" if confidence >= 0.85 else "Medium"
        if "boolean" in t:
            return "High" if confidence >= 0.80 else "Medium"
        if "time" in t:
            return "High" if confidence >= 0.88 else "Medium"
        if "nosql" in t:
            return "High" if confidence >= 0.80 else "Medium"
        return "Medium"
