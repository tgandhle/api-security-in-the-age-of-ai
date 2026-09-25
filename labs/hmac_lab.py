"""HMAC request signing lab.

Run:  python3 hmac_lab.py
      python3 hmac_lab.py --key-file path/to/key   (optional)

No key is written in this file. By default a random 32-byte key is generated
for this run only. In production, services read keys from a mounted file or a
credential broker provided by the platform, not from code or config files.
Environment variables are a weaker option because they can leak to child
processes and diagnostics.
"""
import argparse, hashlib, hmac, secrets, sys

WINDOW_SECONDS = 300  # project baseline: accept requests up to 5 minutes old


def canonical_string(method, host, path, query, ts, nonce, ctype, body):
    body_hash = hashlib.sha256(body).hexdigest()
    return "\n".join([method, host, path, query, str(ts), nonce, ctype, body_hash])


def sign(key, request):
    return hmac.new(key, canonical_string(**request).encode(), hashlib.sha256).hexdigest()


class Verifier:
    """Receiver-side checks, in the order the lesson teaches."""

    def __init__(self, key):
        self.key = key
        self.seen_nonces = {}  # nonce -> timestamp; a shared store in real systems

    def verify(self, request, signature, now):
        if abs(now - request["ts"]) > WINDOW_SECONDS:
            return "reject: outside time window"
        expected = sign(self.key, request)
        if not hmac.compare_digest(signature, expected):
            return "reject: bad signature"
        # Record the nonce only after the signature checks out, so forged
        # requests cannot fill the cache.
        if request["nonce"] in self.seen_nonces:
            return "reject: replayed nonce"
        self.seen_nonces[request["nonce"]] = request["ts"]
        return "accept"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-file", help="read the key from this file instead of generating one")
    args = parser.parse_args()
    if args.key_file:
        with open(args.key_file, "rb") as f:
            key = f.read().strip()
        if len(key) < 32:
            sys.exit("key must be at least 32 bytes for HMAC-SHA256")
        print("key source: file")
    else:
        key = secrets.token_bytes(32)
        print("key source: random, this run only")

    now = 1716307200
    request = dict(method="POST", host="api.hotel.example", path="/v2/transfer", query="",
                   ts=now, nonce="a1b2c3d4-5678", ctype="application/json",
                   body=b'{"linkId":"lnk_7Q2x9","partnerTxnId":"EXA-000042","miles":10000}')
    sig = sign(key, request)

    def attempt(label, req, signature=sig, at=now, verifier=None):
        v = verifier or Verifier(key)
        print(f"{label:<32} {v.verify(req, signature, at)}")

    print()
    print("Part A: integrity. Each attempt uses a fresh verifier.")
    attempt("1. original request", request)
    attempt("2. one digit changed", {**request, "body": request["body"].replace(b"10000", b"90000")})
    attempt("3. spaces added to JSON", {**request, "body": b'{"linkId": "lnk_7Q2x9", "partnerTxnId": "EXA-000042", "miles": 10000}'})
    attempt("4. sent to another host", {**request, "host": "staging.hotel.example"})
    attempt("5. signed with the wrong key", request, signature=sign(secrets.token_bytes(32), request))

    print()
    print("Part B: freshness and replay. One verifier sees every attempt.")
    shared = Verifier(key)
    attempt("6. first delivery", request, verifier=shared)
    attempt("7. exact replay 10s later", request, at=now + 10, verifier=shared)
    attempt("8. replay 10 minutes later", request, at=now + 600, verifier=shared)
    forged = {**request, "nonce": "attacker-nonce"}
    attempt("9. new nonce, old signature", forged, verifier=shared)


if __name__ == "__main__":
    main()
