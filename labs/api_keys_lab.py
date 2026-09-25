"""API key leakage and reuse, entirely in memory. Python standard library only.

Generated credentials never leave memory or appear in output. The vulnerable
log deliberately holds a key in memory so the scanner can demonstrate theft.
This models request handling, not an HTTP server or a production verifier.
"""
import secrets
from urllib.parse import parse_qsl, urlencode, urlsplit


def scan_query_keys(targets):
    """Scan this lab's request-target log format, decoding query names/values."""
    return [value for target in targets
            for name, value in parse_qsl(urlsplit(target).query,
                                         keep_blank_values=True)
            if name == "api_key" and value]


class API:
    def __init__(self, key, protected):
        self.key = key
        self.protected = protected
        self.active = True
        self.logs = []

    def request(self, target, header_key=None):
        pairs = parse_qsl(urlsplit(target).query, keep_blank_values=True)
        query_keys = [v for k, v in pairs if k == "api_key"]
        if self.protected:
            # Fixed route label, never raw URLs or headers, even on rejection.
            self.logs.append("route=balance")
            if query_keys:
                return "reject: query credential"
            candidate = header_key
        else:
            self.logs.append(target)
            candidate = query_keys[0] if query_keys else header_key
        if not candidate or not self.active or not secrets.compare_digest(
                candidate.encode("utf-8"), self.key.encode("utf-8")):
            return "reject: invalid credential"
        return "accept"


def check(label, actual, expected):
    if actual != expected:
        # Do not include data in failures: it could contain a generated key.
        raise RuntimeError("unexpected result: " + label)
    print(f"{label}: {actual}")


def main():
    key = secrets.token_urlsafe(32)
    target = "/balance?" + urlencode({"api_key": key})
    print("key source: random, this run only; values never printed")
    vulnerable = API(key, protected=False)
    check("1. legitimate query request", vulnerable.request(target), "accept")
    stolen = scan_query_keys(vulnerable.logs)
    check("2. query log scanner findings", len(stolen), 1)
    check("3. attacker reuses logged key",
          vulnerable.request("/balance", stolen[0]), "accept")

    protected = API(key, protected=True)
    check("4. query credential after fix", protected.request(target),
          "reject: query credential")
    check("5. legitimate header request", protected.request("/balance", key),
          "accept")
    check("6. protected log scanner findings", len(scan_query_keys(protected.logs)), 0)
    check("7. attacker with only protected logs", protected.request("/balance"),
          "reject: invalid credential")
    check("8. previously stolen key in header", protected.request("/balance", stolen[0]),
          "accept")
    protected.active = False
    check("9. stolen key after revocation", protected.request("/balance", stolen[0]),
          "reject: invalid credential")
    protected.key = secrets.token_urlsafe(32)
    protected.active = True
    check("10. replacement key", protected.request("/balance", protected.key), "accept")
    check("11. old key after replacement", protected.request("/balance", key),
          "reject: invalid credential")
    check("12. wrong key", protected.request("/balance", secrets.token_urlsafe(32)),
          "reject: invalid credential")
    check("13. header plus query credential", protected.request(target, protected.key),
          "reject: query credential")
    encoded = "/balance?%61pi_key=" + key + "&api_key=" + key
    check("14. encoded name and duplicate query scan", len(scan_query_keys([encoded])), 2)
    check("15. encoded query credential", protected.request(encoded),
          "reject: query credential")
    if key in "\n".join(protected.logs) or protected.key in "\n".join(protected.logs):
        raise RuntimeError("protected log leaked a credential")
    check("16. harmless and blank query scan",
          len(scan_query_keys(["/balance?page=1", "/balance?api_key="])), 0)
    check("17. empty query credential", protected.request("/balance?api_key="),
          "reject: query credential")
    print("all lab checks passed")


if __name__ == "__main__":
    main()
