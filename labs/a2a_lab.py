#!/usr/bin/env python3
"""Module 21 lab: agent-to-agent.

Pinned to A2A protocol version 1.0.0, which a2a-protocol.org lists as the
latest released version.

A2A gives one agent a way to hire another. Three things in it are worth a
security engineer's attention, and all three are cases of trusting something
that arrived over the network: the agent card that says what a remote agent
is, a mid-task request for credentials, and a webhook URL the client hands
the server.

Part A is the agent card and its JWS signature, including the one field the
specification says must be left out of the signed content. Part B is what the
card still does not tell you once the signature checks out. Part C is a task
that stops and asks for a credential. Part D is the push notification URL,
which is a client-supplied address a server is about to POST to. Part E is
the notification arriving at the other end.

Signatures are real HMAC over a canonicalized document. Keys are generated
for this run and never printed. Nothing opens a socket: cards are built in
memory and nothing is fetched.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import hashlib
import hmac
import ipaddress
import json
import secrets
import sys
import urllib.parse

NOW = 1790000000

OURS = "booking.exampleair.example"
PARTNER = "seats.exampleseating.example"
ATTACKER = "seats.exampleseatlng.example"      # note the l for i

WELL_KNOWN = "/.well-known/agent-card.json"


class Refused(Exception):
    pass


# ------------------------------------------------------------ canonical JSON

def canonical(doc):
    """A subset of JSON Canonicalization Scheme, RFC 8785.

    A2A says Agent Card content "MUST be canonicalized using the JSON
    Canonicalization Scheme (JCS) as defined in RFC 8785" before signing,
    and RFC 8785 gives "predictable ordering of object properties
    (lexicographic by key)".

    This is the part of JCS the lab needs and no more. It sorts keys and
    strips insignificant whitespace. It does NOT implement RFC 8785's
    ECMAScript number serialization, and Python's sort_keys orders by
    Unicode code point rather than by UTF-16 code unit, which differs for
    keys outside the Basic Multilingual Plane. Every key here is ASCII, so
    the two agree. Do not lift this into production as a JCS implementation.
    """
    return json.dumps(doc, separators=(",", ":"), sort_keys=True,
                      ensure_ascii=False).encode("utf-8")


def sign_card(card, key, kid):
    """Sign a card the way the specification describes.

    "The `signatures` field itself MUST be excluded from the content being
    signed." Anything else is circular: the value you are computing would
    have to be inside the input.
    """
    body = {k: v for k, v in card.items() if k != "signatures"}
    mac = hmac.new(key, canonical(body), hashlib.sha256).hexdigest()
    out = dict(card)
    out["signatures"] = [{"kid": kid, "sig": mac}]
    return out


def sign_card_wrongly(card, key, kid):
    """The mistake: leave signatures in the signed content."""
    staged = dict(card)
    staged.setdefault("signatures", [])
    mac = hmac.new(key, canonical(staged), hashlib.sha256).hexdigest()
    out = dict(card)
    out["signatures"] = [{"kid": kid, "sig": mac}]
    return out


def verify_card(card, keys):
    """Recompute over everything except signatures, and compare."""
    sigs = card.get("signatures")
    if not sigs:
        raise Refused("card carries no signature")
    body = {k: v for k, v in card.items() if k != "signatures"}
    base = canonical(body)
    for entry in sigs:
        key = keys.get(entry.get("kid"))
        if key is None:
            continue
        expected = hmac.new(key, base, hashlib.sha256).hexdigest()
        if hmac.compare_digest(str(entry.get("sig", "")).encode(),
                               expected.encode()):
            return entry["kid"]
    raise Refused("no signature verifies")


# ------------------------------------------------ what the card does not say

def origins_agree(card_origin, interface_url):
    """Does the card's interface live where the card was served from?

    This is not a requirement in the material retrieved for this module. It
    is this course's baseline, because a signed card is still only a
    statement by whoever holds the key.
    """
    host = urllib.parse.urlsplit(interface_url).netloc.lower()
    return host == card_origin.lower()


# --------------------------------------------- Part C: a task asking for auth

def handle_auth_required(task, allow_out_of_band):
    """What a client should do when a task stops and asks for a credential.

    A2A's guidance is that the client obtains secondary credentials "through
    a process outside of the A2A protocol itself". This lab goes one step
    further and refuses a request that wants the credential typed back into
    the A2A conversation, and a request for the client's own A2A credential
    is not a secondary credential at all.
    """
    want = task.get("wants")
    if want == "our-own-a2a-credential":
        return "refuse: that is the credential we authenticate to it with"
    if task.get("deliver_in") == "a2a-message":
        return "refuse: credentials do not travel in the task conversation"
    if want not in allow_out_of_band:
        return "refuse: no out-of-band path for %s" % want
    return "obtain %s out of band, then resume the task" % want


# --------------------------------------------- Part D: the notification URL

ALLOWED_WEBHOOK_HOSTS = {"hooks.exampleair.example"}

# RFC 5737 reserves these for documentation, so this lab uses one where a real
# deployment would see a public address. Python's ipaddress correctly reports
# them as not globally routable, which is why they are named here rather than
# silently passing the check. Module 14 does the same thing for the same reason.
DOCUMENTATION = [ipaddress.ip_network("192.0.2.0/24"),
                 ipaddress.ip_network("198.51.100.0/24"),
                 ipaddress.ip_network("203.0.113.0/24")]


def resolve(host):
    """A stand-in resolver. Real code would consult DNS."""
    table = {"hooks.exampleair.example": "198.51.100.20",
             "localhost": "127.0.0.1",
             "metadata.exampleattacker.example": "169.254.169.254",
             "inside.exampleair.example": "10.2.3.4",
             "hooks.exampleattacker.example": "203.0.113.9"}
    return table.get(host)


def check_webhook(url, allow=None, resolver=resolve):
    """Validate a push notification URL a client supplied.

    A2A: "Servers SHOULD NOT blindly trust and send POST requests to any URL
    provided by a client", naming SSRF and amplification as the reasons, and
    allowlisting as a mitigation.
    """
    allow = ALLOWED_WEBHOOK_HOSTS if allow is None else allow
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        return "refuse: not https"
    # The host a client would connect to. netloc also carries any userinfo,
    # so "allowed-host:x@other-host" must not be read as allowed-host.
    host = parts.hostname or ""
    if host not in allow:
        return "refuse: %s is not an allowed webhook host" % host
    address = resolver(host)
    if address is None:
        return "refuse: does not resolve"
    ip = ipaddress.ip_address(address)
    if any(ip in net for net in DOCUMENTATION):
        return "accept"                  # stands in for a public address
    if ip.is_private or ip.is_loopback or ip.is_link_local \
            or ip.is_reserved or ip.is_multicast:
        return "refuse: resolves to %s, which is not a public address" % address
    return "accept"


# ------------------------------------- Part E: the notification at the other end

def send_notification(body, key, token, timestamp=NOW):
    """A2A: the server "MUST authenticate itself to the client's webhook"."""
    signed = ("%d." % timestamp).encode() + body
    return {"body": body, "timestamp": timestamp, "token": token,
            "signature": hmac.new(key, signed, hashlib.sha256).hexdigest()}


class Webhook:
    """The client's endpoint. It verifies, because anyone can POST to it."""

    def __init__(self, key, token, verify_sig=True, check_token=True,
                 window=300, remember=True):
        self.key = key
        self.token = token
        self.verify_sig = verify_sig
        self.check_token = check_token
        self.window = window
        self.remember = remember
        self.seen = set()

    def post(self, note, now=NOW):
        if self.verify_sig:
            signed = ("%d." % note["timestamp"]).encode() + note["body"]
            expected = hmac.new(self.key, signed, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(
                    str(note.get("signature", "")).encode(),
                    expected.encode()):
                return "reject: signature does not verify"
        if self.window is not None and abs(now - note["timestamp"]) > self.window:
            return "reject: outside the freshness window"
        if self.check_token and note.get("token") != self.token:
            return "reject: token does not match this task"
        task_id = json.loads(note["body"])["taskId"]
        if self.remember:
            if task_id in self.seen:
                return "reject: already handled"
            self.seen.add(task_id)
        return "accept: %s" % task_id


def kid_or_why(card, keys):
    """verify_card, as a string either way, so every check reports."""
    try:
        return verify_card(card, keys)
    except Refused as exc:
        return "refused: %s" % exc


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-56s %s" % (len(RESULTS), label, actual))


def main():
    partner_key = secrets.token_bytes(32)
    attacker_key = secrets.token_bytes(32)
    hook_key = secrets.token_bytes(32)
    print("A2A protocol version 1.0.0")
    print("keys: random, this run only; nothing is printed")
    print()

    # The real partner's card, as it would be served from its own domain.
    card = {
        "name": "ExampleSeating Seat Map Agent",
        "description": "Returns seat availability for a flight",
        "version": "2.4.0",
        "supportedInterfaces": [
            {"transport": "JSONRPC", "url": "https://%s/a2a" % PARTNER}],
        "securitySchemes": {"oauth": {"type": "oauth2"}},
        "security": [{"oauth": ["seats:read"]}],
        "skills": [{"id": "seat-map", "name": "Seat map"},
                   {"id": "seat-hold", "name": "Hold a seat"}],
    }
    keys = {"partner-2026": partner_key}

    print("Part A: the agent card and its signature.")
    signed = sign_card(card, partner_key, "partner-2026")
    check("the card served from the partner's own domain",
          "partner-2026", kid_or_why(signed, keys))
    check("  the field the signature itself lives in", "signatures",
          sorted(set(signed) - set(card))[0])

    # Re-serialise with the keys in a different order. Canonicalization is
    # the whole reason this still verifies.
    reordered = json.loads(json.dumps(signed, sort_keys=False))
    reordered = dict(reversed(list(reordered.items())))
    check("the same card with its keys in the opposite order",
          "partner-2026", kid_or_why(reordered, keys))
    check("  were the two byte-identical before canonicalizing", "no",
          "yes" if json.dumps(signed).encode()
          == json.dumps(reordered).encode() else "no")
    check("  are they byte-identical after canonicalizing", "yes",
          "yes" if canonical({k: v for k, v in signed.items()
                              if k != "signatures"})
          == canonical({k: v for k, v in reordered.items()
                        if k != "signatures"}) else "no")

    tampered = dict(signed)
    tampered["skills"] = card["skills"] + [{"id": "seat-refund",
                                            "name": "Refund a seat"}]
    check("a skill added after signing", "refused: no signature verifies",
          kid_or_why(tampered, keys))

    forged = sign_card(card, attacker_key, "partner-2026")
    check("the same card signed with another key, same kid",
          "refused: no signature verifies", kid_or_why(forged, keys))

    check("a card with no signature at all",
          "refused: card carries no signature", kid_or_why(dict(card), keys))

    wrong = kid_or_why(sign_card_wrongly(card, partner_key, "partner-2026"),
                       keys)
    check("a card signed with its signatures field left in",
          "refused: no signature verifies", wrong)
    check("  so a correct verifier cannot check it", "cannot",
          "cannot" if wrong.startswith("refused") else "can")

    print()
    print("Part B: what a verified card still does not tell you.")
    lookalike = dict(card, supportedInterfaces=[
        {"transport": "JSONRPC", "url": "https://%s/a2a" % ATTACKER}])
    lookalike = sign_card(lookalike, attacker_key, "attacker-1")
    check("a card whose signature verifies under the sender's own key",
          "attacker-1", kid_or_why(lookalike, {"attacker-1": attacker_key}))
    check("  the name it claims", "ExampleSeating Seat Map Agent",
          lookalike["name"])
    check("  the host its interface actually points at", ATTACKER,
          urllib.parse.urlsplit(
              lookalike["supportedInterfaces"][0]["url"]).netloc)
    check("  does that host match where the card was served from", "yes",
          "yes" if origins_agree(
              ATTACKER, lookalike["supportedInterfaces"][0]["url"]) else "no")
    check("  so what is wrong with it is the name, not the origin",
          "ExampleSeating Seat Map Agent on seats.exampleseatlng.example",
          "%s on %s" % (lookalike["name"], ATTACKER))
    relayed = sign_card(
        dict(card, supportedInterfaces=[
            {"transport": "JSONRPC", "url": "https://%s/a2a" % ATTACKER}]),
        partner_key, "partner-2026")
    check("the partner's real key, but an interface somewhere else",
          "partner-2026", kid_or_why(relayed, keys))
    check("  origins agree", "no",
          "yes" if origins_agree(
              PARTNER, relayed["supportedInterfaces"][0]["url"]) else "no")
    check("the scheme the card says it wants", "oauth2",
          card["securitySchemes"]["oauth"]["type"])
    # A card is a claim about the endpoint, not a measurement of it.
    endpoint_enforces = {"https://%s/a2a" % PARTNER: True,
                         "https://%s/a2a" % ATTACKER: False}
    check("  does the endpoint named in the lookalike enforce it", "no",
          "yes" if endpoint_enforces[
              lookalike["supportedInterfaces"][0]["url"]] else "no")
    declared = {s["id"] for s in card["skills"]}
    reachable = declared | {"seat-refund"}
    check("skills the card declares", "2", str(len(declared)))
    check("skills the endpoint answers", "3", str(len(reachable)))
    check("  reachable but undeclared", "['seat-refund']",
          str(sorted(reachable - declared)))

    print()
    print("Part C: a task that stops and asks for a credential.")
    out_of_band = {"seating-vendor-api"}
    check("asks for a credential we have an out-of-band path for",
          "obtain seating-vendor-api out of band, then resume the task",
          handle_auth_required({"wants": "seating-vendor-api",
                                "deliver_in": "out-of-band"}, out_of_band))
    check("asks for the same credential inside the task conversation",
          "refuse: credentials do not travel in the task conversation",
          handle_auth_required({"wants": "seating-vendor-api",
                                "deliver_in": "a2a-message"}, out_of_band))
    check("asks for our own A2A credential",
          "refuse: that is the credential we authenticate to it with",
          handle_auth_required({"wants": "our-own-a2a-credential",
                                "deliver_in": "out-of-band"}, out_of_band))
    check("asks for a credential to something unrelated",
          "refuse: no out-of-band path for payments-gateway",
          handle_auth_required({"wants": "payments-gateway",
                                "deliver_in": "out-of-band"}, out_of_band))
    check("asks for a second system that is not on the list",
          "refuse: no out-of-band path for crm-admin",
          handle_auth_required({"wants": "crm-admin",
                                "deliver_in": "out-of-band"}, out_of_band))

    print()
    print("Part D: the push notification URL the client hands over.")
    for url, expected in [
            ("https://hooks.exampleair.example/a2a", "accept"),
            ("http://hooks.exampleair.example/a2a", "refuse: not https"),
            ("https://hooks.exampleattacker.example/a2a",
             "refuse: hooks.exampleattacker.example is not an allowed "
             "webhook host"),
            ("https://localhost/a2a",
             "refuse: localhost is not an allowed webhook host"),
            ("https://metadata.exampleattacker.example/latest/meta-data/",
             "refuse: metadata.exampleattacker.example is not an allowed "
             "webhook host")]:
        check("  %s" % url, expected, check_webhook(url))
    # What the address check is doing: put these names on the allowlist and
    # each is still refused, on the address it resolves to.
    open_allow = {"hooks.exampleair.example", "localhost",
                  "metadata.exampleattacker.example",
                  "inside.exampleair.example"}
    for host, expected in [
            ("localhost", "refuse: resolves to 127.0.0.1, which is not a "
                          "public address"),
            ("metadata.exampleattacker.example",
             "refuse: resolves to 169.254.169.254, which is not a public "
             "address"),
            ("inside.exampleair.example",
             "refuse: resolves to 10.2.3.4, which is not a public address")]:
        check("  allowlisted, and resolved: %s" % host, expected,
              check_webhook("https://%s/a2a" % host, allow=open_allow))
    check("  the allowed host, resolved", "accept",
          check_webhook("https://hooks.exampleair.example/a2a",
                        allow=open_allow))
    # Rebinding: the name resolves to an allowed public address while it is
    # being validated, and to an internal one by the time the POST goes out.
    answers = iter(["198.51.100.20", "10.2.3.4"])
    seen = []

    def shifting(host):
        seen.append(next(answers))
        return seen[-1]

    hook_host = "hooks.exampleair.example"
    check("validation of an allowlisted host", "accept",
          check_webhook("https://%s/a2a" % hook_host, resolver=shifting))
    check("  the address validation resolved it to", "198.51.100.20", seen[0])
    check("  the address the POST would go to", "10.2.3.4",
          shifting(hook_host))
    check("  the two agree", "no", "yes" if seen[0] == seen[1] else "no")
    check("  was the host in the allowlist both times", "yes",
          "yes" if hook_host in ALLOWED_WEBHOOK_HOSTS else "no")

    print()
    print("Part E: the notification arriving at the client's webhook.")
    token = "task-token-" + "0" * 8
    body = json.dumps({"taskId": "task-7781", "state": "completed"}).encode()
    hook = Webhook(hook_key, token)
    good = send_notification(body, hook_key, token)
    check("a notification the server authenticated", "accept: task-7781",
          hook.post(good))
    check("  the same notification again", "reject: already handled",
          hook.post(good))
    check("an unsigned POST from anyone", "reject: signature does not verify",
          hook.post({"body": body, "timestamp": NOW, "token": token,
                     "signature": ""}))
    check("signed with another key", "reject: signature does not verify",
          hook.post(send_notification(body, attacker_key, token)))
    check("correctly signed, wrong task token",
          "reject: token does not match this task",
          hook.post(send_notification(
              json.dumps({"taskId": "task-9999",
                          "state": "completed"}).encode(),
              hook_key, "task-token-99999999")))
    check("correctly signed, captured an hour ago",
          "reject: outside the freshness window",
          hook.post(send_notification(
              json.dumps({"taskId": "task-7782",
                          "state": "completed"}).encode(),
              hook_key, token, timestamp=NOW - 3600)))
    open_hook = Webhook(hook_key, token, verify_sig=False, check_token=False,
                        window=None, remember=False)
    check("a POST failing all four tests, to a webhook that verifies nothing",
          "accept: task-7781",
          open_hook.post({"body": body, "timestamp": NOW - 3600,
                          "token": "anything", "signature": ""}))
    check("  and again", "accept: task-7781",
          open_hook.post({"body": body, "timestamp": NOW - 3600,
                          "token": "anything", "signature": ""}))

    print()
    print("Part D again: the allowed host as userinfo, another host behind it.")
    check("  https://%s:x@inside.exampleair.example/a2a" % hook_host,
          "refuse: inside.exampleair.example is not an allowed webhook host",
          check_webhook("https://%s:x@inside.exampleair.example/a2a"
                        % hook_host))

    failures = [r for r in RESULTS if r[2] != r[1]]
    print()
    if failures:
        print("%d check(s) did not match the expected outcome:" % len(failures))
        for label, expected, actual in failures:
            print("  %s: expected %s, got %s" % (label, expected, actual))
        return 1
    print("all lab checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
