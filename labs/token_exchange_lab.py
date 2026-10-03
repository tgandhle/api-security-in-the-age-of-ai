#!/usr/bin/env python3
"""Module 19 lab: delegation and token exchange.

Parts 1 to 3 assumed the caller was the party doing the work. An agent is
not. It holds a token that came from somewhere else, and it calls on behalf
of a person who is not in the request. RFC 8693 is the standard way to turn
one token into another, and it has two very different modes.

Part A puts four ways of making that call side by side: forwarding the user's
token untouched, using the agent's own service credential, exchanging for an
impersonation token, and exchanging for a delegation token. The only one that
tells a resource server both who is calling and who it is for is the last.
Part B is the parameter rules the specification actually states. Part C is
"may_act", the subject's say in who may act for it. Part D is scope,
audience and lifetime, the things that bound what comes out. Part E is the
delegation chain and the one MUST that RFC 8693 places on whoever consumes
the token. Part F is what an exchange does not do.

The tokens here are real HS256 JWTs: minted with hmac, verified with
hmac.compare_digest, decoded with json. The one signing key is generated at
random for this run and is never printed.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import base64
import hashlib
import hmac
import itertools
import json
import secrets
import sys

NOW = 1790000000          # a fixed clock, so the output is the same every run

GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
T_ACCESS = "urn:ietf:params:oauth:token-type:access_token"
T_REFRESH = "urn:ietf:params:oauth:token-type:refresh_token"
T_ID = "urn:ietf:params:oauth:token-type:id_token"
T_JWT = "urn:ietf:params:oauth:token-type:jwt"
T_SAML2 = "urn:ietf:params:oauth:token-type:saml2"
KNOWN_TYPES = {T_ACCESS, T_REFRESH, T_ID, T_JWT, T_SAML2}

ISSUER = "https://id.exampleair.example"
AGENT_ISSUER = "https://id.exampleagent.example"
BOOKINGS = "https://bookings.exampleair.example"
PAYMENTS = "https://payments.exampleair.example"

ALL_SCOPES = "bookings:read bookings:write loyalty:write payments:write profile:read"

JTI = itertools.count(1)  # one jti per issued token, the same every run


class Refused(Exception):
    """An OAuth error response. code is the error parameter value."""

    def __init__(self, code, why):
        Exception.__init__(self, "%s: %s" % (code, why))
        self.code = code
        self.why = why


# ---------------------------------------------------------------- JWT plumbing

def b64u(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def mint(payload, key):
    head = b64u(json.dumps({"alg": "HS256", "typ": "JWT"},
                           separators=(",", ":"), sort_keys=True).encode())
    body = b64u(json.dumps(payload, separators=(",", ":"),
                           sort_keys=True).encode())
    signed = ("%s.%s" % (head, body)).encode("ascii")
    return "%s.%s.%s" % (head, body,
                         b64u(hmac.new(key, signed, hashlib.sha256).digest()))


def read(token, key, now=NOW):
    """Verify and decode. This is the whole of what a bearer JWT tells you."""
    try:
        head, body, sig = token.split(".")
    except ValueError:
        raise Refused("invalid_request", "not three dot-separated parts")
    signed = ("%s.%s" % (head, body)).encode("ascii")
    expected = b64u(hmac.new(key, signed, hashlib.sha256).digest())
    if not hmac.compare_digest(sig, expected):
        raise Refused("invalid_request", "signature does not verify")
    payload = json.loads(unb64u(body))
    if payload.get("exp", 0) <= now:
        raise Refused("invalid_request", "expired")
    return payload


def chain(payload):
    """The actors in the token, current first, least recent last."""
    out = []
    act = payload.get("act")
    while act:
        out.append(act["sub"])
        act = act.get("act")
    return out


def caller(payload):
    """The party actually making the call, as the token states it."""
    act = payload.get("act")
    return act["sub"] if act else payload["sub"]


def who_for(payload):
    """The party the call is being made for."""
    return payload["sub"]


def pair(token, key):
    payload = read(token, key)
    return "%s / %s" % (caller(payload), who_for(payload))


# ------------------------------------------------------------ the two servers

class AuthorizationServer:
    """An RFC 8693 token exchange endpoint.

    The flags are this deployment's policy, not the specification. RFC 8693
    makes audience, resource and scope all OPTIONAL and says nothing about
    capping the lifetime. Every one of them is a local decision, which is
    the point: the specification does not stop you issuing a token that is
    broader and longer-lived than the one you were handed.
    """

    def __init__(self, key, audiences, require_may_act=True,
                 default_scope_to_subject=True, cap_lifetime=True,
                 require_target=True, revoked=None):
        self.key = key
        self.audiences = set(audiences)
        self.require_may_act = require_may_act
        self.default_scope_to_subject = default_scope_to_subject
        self.cap_lifetime = cap_lifetime
        self.require_target = require_target
        self.revoked = set(revoked or ())

    def exchange(self, grant_type=None, subject_token=None,
                 subject_token_type=None, actor_token=None,
                 actor_token_type=None, audience=None, resource=None,
                 scope=None, requested_token_type=None, want_seconds=3600,
                 now=NOW):
        # RFC 8693 section 2.1. grant_type, subject_token and
        # subject_token_type are the three REQUIRED parameters.
        if grant_type != GRANT:
            raise Refused("unsupported_grant_type", "not a token exchange")
        if subject_token is None or subject_token_type is None:
            raise Refused("invalid_request",
                          "subject_token and subject_token_type are both required")
        if subject_token_type not in KNOWN_TYPES:
            raise Refused("invalid_request", "unknown subject_token_type")
        # actor_token_type is REQUIRED when actor_token is present and
        # MUST NOT be included otherwise.
        if actor_token is not None and actor_token_type is None:
            raise Refused("invalid_request",
                          "actor_token_type is required when actor_token is present")
        if actor_token is None and actor_token_type is not None:
            raise Refused("invalid_request",
                          "actor_token_type must not be sent without actor_token")

        subject = read(subject_token, self.key, now)
        if subject.get("jti") in self.revoked:
            raise Refused("invalid_request", "the subject token has been revoked")
        actor = None
        if actor_token is not None:
            actor = read(actor_token, self.key, now)

        target = audience or resource
        if target is None:
            if self.require_target:
                raise Refused("invalid_request",
                              "this deployment requires audience or resource")
            target = None
        elif target not in self.audiences:
            # RFC 8693 section 2.2.2 names invalid_target for exactly this.
            raise Refused("invalid_target", "no such target service")

        held = set(subject.get("scope", "").split())
        if scope is None:
            if not self.default_scope_to_subject:
                raise Refused("invalid_request",
                              "this deployment requires scope to be stated")
            granted = set(held)
        else:
            asked = set(scope.split())
            if not asked <= held:
                raise Refused("invalid_request",
                              "requested scope exceeds the subject token's scope")
            granted = asked

        if actor is not None and self.require_may_act:
            # RFC 8693 section 4.4: the subject token's may_act claim says
            # who is allowed to become the actor. Matching on sub alone is
            # not enough, because sub is only unique within an issuer.
            allowed = subject.get("may_act")
            if not allowed:
                raise Refused("invalid_request",
                              "the subject token names no authorized actor")
            if (allowed.get("iss"), allowed.get("sub")) \
                    != (actor.get("iss"), actor.get("sub")):
                raise Refused("invalid_request",
                              "this actor is not the authorized actor")

        left = subject["exp"] - now
        ttl = min(want_seconds, left) if self.cap_lifetime else want_seconds

        payload = {"iss": ISSUER, "aud": target, "sub": subject["sub"],
                   "iat": now, "exp": now + ttl,
                   "jti": "exchanged-%d" % next(JTI),
                   "scope": " ".join(sorted(granted))}
        if actor is not None:
            # RFC 8693 section 4.1: the outermost act claim is the current
            # actor, prior actors nest inside it.
            act = {"iss": actor["iss"], "sub": actor["sub"]}
            if "act" in subject:
                act["act"] = subject["act"]
            payload["act"] = act

        issued = requested_token_type or T_ACCESS
        # section 2.2.1: N_A when the issued token is not usable as an
        # access token. An id_token, a refresh token and a SAML assertion
        # are not; this deployment treats the access_token and jwt types
        # as bearer access tokens.
        usable = issued in (T_ACCESS, T_JWT)
        response = {"access_token": mint(payload, self.key),
                    "issued_token_type": issued,
                    "token_type": "Bearer" if usable else "N_A",
                    "expires_in": ttl}
        if scope is None or set(scope.split()) != granted:
            # section 2.2.1: scope is OPTIONAL only when it is identical to
            # what the client asked for.
            response["scope"] = " ".join(sorted(granted))
        return response


class ResourceServer:
    """allowed_actors is a list of (iss, sub) pairs, matched together."""

    def __init__(self, name, key, allowed_actors, walk_chain=False):
        self.name = name
        self.key = key
        self.allowed_actors = set(allowed_actors)
        self.walk_chain = walk_chain

    def call(self, token, need, now=NOW):
        try:
            payload = read(token, self.key, now)
        except Refused as exc:
            return "refused: %s" % exc.why
        if payload.get("aud") != self.name:
            return "refused: wrong audience"
        if need not in payload.get("scope", "").split():
            return "refused: %s not in scope" % need
        act = payload.get("act")
        if act is None:
            return "allowed, caller is %s" % payload["sub"]
        current = act["sub"]
        if (act.get("iss"), current) in self.allowed_actors:
            return "allowed, %s for %s" % (current, payload["sub"])
        if self.walk_chain:
            # The bug. Section 4.1 says the consumer MUST only consider the
            # top-level claims and the current actor.
            prior = act.get("act")
            while prior:
                if (prior.get("iss"), prior["sub"]) in self.allowed_actors:
                    return "allowed, %s for %s on a prior actor" \
                        % (current, payload["sub"])
                prior = prior.get("act")
        return "refused: %s is not an allowed actor" % current


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-52s %s" % (len(RESULTS), label, actual))


def attempt(server, **kwargs):
    """Run an exchange and return the response, or the Refused exception it raised."""
    try:
        return server.exchange(**kwargs)
    except Refused as exc:
        return exc


def code_of(outcome):
    return outcome.code if isinstance(outcome, Refused) else "issued"


def main():
    key = secrets.token_bytes(32)
    print("signing key: random, this run only; no key or token text is printed")
    print("clock is fixed at %d" % NOW)
    print()

    user = {"iss": ISSUER, "sub": "traveller-8812", "aud": BOOKINGS,
            "iat": NOW - 60, "exp": NOW + 300, "jti": "user-token-1",
            "scope": ALL_SCOPES,
            "may_act": {"iss": AGENT_ISSUER,
                        "sub": "https://assistant.exampleagent.example"}}
    user_token = mint(user, key)

    assistant = {"iss": AGENT_ISSUER,
                 "sub": "https://assistant.exampleagent.example",
                 "iat": NOW - 60, "exp": NOW + 3600, "jti": "agent-token-1"}
    assistant_token = mint(assistant, key)

    stranger = {"iss": AGENT_ISSUER,
                "sub": "https://other.exampleagent.example",
                "iat": NOW - 60, "exp": NOW + 3600, "jti": "agent-token-2"}
    stranger_token = mint(stranger, key)

    server = AuthorizationServer(key, [BOOKINGS, PAYMENTS])
    bookings = ResourceServer(
        BOOKINGS, key,
        allowed_actors=[(AGENT_ISSUER,
                         "https://assistant.exampleagent.example")])

    print("Part A: four ways an agent can call a downstream service.")

    # 1. Passthrough: the agent forwards the user's own token untouched.
    # 2. The agent's own service credential, user named nowhere.
    # 3. Impersonation: an exchange with no actor_token.
    # 4. Delegation: an exchange with an actor_token.
    service_credential = {"iss": ISSUER,
                          "sub": "https://assistant.exampleagent.example",
                          "aud": BOOKINGS, "iat": NOW - 60, "exp": NOW + 3600,
                          "jti": "svc-standing", "scope": "bookings:write"}
    service_token = mint(service_credential, key)

    impersonation = server.exchange(
        grant_type=GRANT, subject_token=user_token,
        subject_token_type=T_ACCESS, audience=BOOKINGS,
        scope="bookings:write")
    delegation = server.exchange(
        grant_type=GRANT, subject_token=user_token,
        subject_token_type=T_ACCESS, actor_token=assistant_token,
        actor_token_type=T_JWT, audience=BOOKINGS, scope="bookings:write")

    imp = read(impersonation["access_token"], key)
    dele = read(delegation["access_token"], key)

    print("  each line is: who the token says is calling / who it is for")
    check("passthrough, the user's own token forwarded",
          "traveller-8812 / traveller-8812", pair(user_token, key))
    check("the agent's own service credential",
          "https://assistant.exampleagent.example / "
          "https://assistant.exampleagent.example", pair(service_token, key))
    check("impersonation, an exchange with no actor_token",
          "traveller-8812 / traveller-8812",
          pair(impersonation["access_token"], key))
    check("delegation, an exchange with an actor_token",
          "https://assistant.exampleagent.example / traveller-8812",
          pair(delegation["access_token"], key))
    check("the act claim on the impersonation token", "absent",
          "present" if "act" in imp else "absent")
    check("the act claim on the delegation token", "present",
          "present" if "act" in dele else "absent")
    check("what the booking service logs for impersonation",
          "allowed, caller is traveller-8812",
          bookings.call(impersonation["access_token"], "bookings:write"))
    check("what it logs for delegation",
          "allowed, https://assistant.exampleagent.example for traveller-8812",
          bookings.call(delegation["access_token"], "bookings:write"))
    forwarded = [s for s in ALL_SCOPES.split()
                 if bookings.call(user_token, s).startswith("allowed")]
    check("operations passthrough reaches, of five", "5",
          str(len(forwarded)))
    check("operations the delegated token reaches, of five", "1",
          str(len([s for s in ALL_SCOPES.split()
                   if bookings.call(delegation["access_token"],
                                    s).startswith("allowed")])))

    print()
    print("Part B: the parameter rules RFC 8693 states.")

    check("no subject_token at all", "invalid_request",
          code_of(attempt(server, grant_type=GRANT,
                          subject_token_type=T_ACCESS, audience=BOOKINGS)))
    check("a subject_token with no subject_token_type", "invalid_request",
          code_of(attempt(server, grant_type=GRANT, subject_token=user_token,
                          audience=BOOKINGS)))
    check("a subject_token_type nobody registered", "invalid_request",
          code_of(attempt(server, grant_type=GRANT, subject_token=user_token,
                          subject_token_type="urn:example:made-up",
                          audience=BOOKINGS)))
    check("an actor_token with no actor_token_type", "invalid_request",
          code_of(attempt(server, grant_type=GRANT, subject_token=user_token,
                          subject_token_type=T_ACCESS,
                          actor_token=assistant_token, audience=BOOKINGS)))
    check("an actor_token_type with no actor_token", "invalid_request",
          code_of(attempt(server, grant_type=GRANT, subject_token=user_token,
                          subject_token_type=T_ACCESS,
                          actor_token_type=T_JWT, audience=BOOKINGS)))
    check("an authorization code grant sent here", "unsupported_grant_type",
          code_of(attempt(server, grant_type="authorization_code",
                          subject_token=user_token,
                          subject_token_type=T_ACCESS, audience=BOOKINGS)))
    as_jwt = server.exchange(
        grant_type=GRANT, subject_token=user_token,
        subject_token_type=T_ACCESS, audience=BOOKINGS,
        scope="bookings:read", requested_token_type=T_JWT)
    check("issued_token_type when a jwt was requested", T_JWT,
          as_jwt["issued_token_type"])
    check("token_type alongside it", "Bearer", as_jwt["token_type"])
    id_token = server.exchange(
        grant_type=GRANT, subject_token=user_token,
        subject_token_type=T_ACCESS, audience=BOOKINGS,
        scope="profile:read", requested_token_type=T_ID)
    check("token_type when an id_token was requested", "N_A",
          id_token["token_type"])

    print()
    print("Part C: may_act, the subject's say in who may act for it.")

    check("the actor the subject token names", "issued",
          code_of(attempt(server, grant_type=GRANT, subject_token=user_token,
                          subject_token_type=T_ACCESS,
                          actor_token=assistant_token, actor_token_type=T_JWT,
                          audience=BOOKINGS, scope="bookings:write")))
    check("a different agent, same request", "invalid_request",
          code_of(attempt(server, grant_type=GRANT, subject_token=user_token,
                          subject_token_type=T_ACCESS,
                          actor_token=stranger_token, actor_token_type=T_JWT,
                          audience=BOOKINGS, scope="bookings:write")))

    bare = dict(user, jti="user-token-2")
    del bare["may_act"]
    bare_token = mint(bare, key)
    check("a subject token with no may_act claim", "invalid_request",
          code_of(attempt(server, grant_type=GRANT, subject_token=bare_token,
                          subject_token_type=T_ACCESS,
                          actor_token=assistant_token, actor_token_type=T_JWT,
                          audience=BOOKINGS, scope="bookings:write")))
    check("the same request to a server that does not check", "issued",
          code_of(attempt(
              AuthorizationServer(key, [BOOKINGS], require_may_act=False),
              grant_type=GRANT, subject_token=bare_token,
              subject_token_type=T_ACCESS, actor_token=assistant_token,
              actor_token_type=T_JWT, audience=BOOKINGS,
              scope="bookings:write")))

    # Same sub, different issuer. Matching on sub alone would let this in.
    lookalike = dict(assistant, iss="https://id.attacker.example",
                     jti="agent-token-3")
    check("an agent with the same sub from another issuer", "invalid_request",
          code_of(attempt(server, grant_type=GRANT, subject_token=user_token,
                          subject_token_type=T_ACCESS,
                          actor_token=mint(lookalike, key),
                          actor_token_type=T_JWT, audience=BOOKINGS,
                          scope="bookings:write")))

    print()
    print("Part D: scope, audience and lifetime, the bounds on what comes out.")

    check("scopes the user's own token carries", "5",
          str(len(read(user_token, key)["scope"].split())))
    check("scopes in the token issued for bookings:write", "1",
          str(len(read(delegation["access_token"], key)["scope"].split())))
    wide = server.exchange(grant_type=GRANT, subject_token=user_token,
                           subject_token_type=T_ACCESS,
                           actor_token=assistant_token,
                           actor_token_type=T_JWT, audience=BOOKINGS)
    check("scopes when the client omits scope entirely", "5",
          str(len(read(wide["access_token"], key)["scope"].split())))
    strict = AuthorizationServer(key, [BOOKINGS],
                                 default_scope_to_subject=False)
    check("the same omission on a server that insists", "invalid_request",
          code_of(attempt(strict, grant_type=GRANT, subject_token=user_token,
                          subject_token_type=T_ACCESS,
                          actor_token=assistant_token, actor_token_type=T_JWT,
                          audience=BOOKINGS)))
    check("asking for a scope the subject does not hold", "invalid_request",
          code_of(attempt(server, grant_type=GRANT, subject_token=user_token,
                          subject_token_type=T_ACCESS, audience=BOOKINGS,
                          scope="bookings:write refunds:write")))
    check("a target service this server has never heard of", "invalid_target",
          code_of(attempt(server, grant_type=GRANT, subject_token=user_token,
                          subject_token_type=T_ACCESS,
                          audience="https://bookings.attacker.example",
                          scope="bookings:write")))
    check("a bookings token presented to the payments service",
          "refused: wrong audience",
          ResourceServer(PAYMENTS, key, allowed_actors=[]).call(
              delegation["access_token"], "payments:write"))
    loose = AuthorizationServer(key, [BOOKINGS], require_target=False)
    untargeted = loose.exchange(grant_type=GRANT, subject_token=user_token,
                                subject_token_type=T_ACCESS,
                                actor_token=assistant_token,
                                actor_token_type=T_JWT, scope="bookings:write")
    check("aud on a token issued with no target named", "None",
          str(read(untargeted["access_token"], key)["aud"]))
    check("seconds left on the user's token", "300",
          str(read(user_token, key)["exp"] - NOW))
    check("expires_in on the exchanged token", "300",
          str(delegation["expires_in"]))
    uncapped = AuthorizationServer(key, [BOOKINGS], cap_lifetime=False)
    check("the same exchange on a server that does not cap it", "3600",
          str(uncapped.exchange(
              grant_type=GRANT, subject_token=user_token,
              subject_token_type=T_ACCESS, actor_token=assistant_token,
              actor_token_type=T_JWT, audience=BOOKINGS,
              scope="bookings:write")["expires_in"]))

    print()
    print("Part E: the delegation chain, and the one MUST on reading it.")

    # The assistant hands off to a pricing service, which hands off to a
    # seat-map service. Each hop exchanges the token it holds.
    pricing = {"iss": AGENT_ISSUER, "sub": "https://pricing.exampleair.example",
               "iat": NOW - 60, "exp": NOW + 3600, "jti": "svc-1"}
    seats = {"iss": AGENT_ISSUER, "sub": "https://seats.exampleair.example",
             "iat": NOW - 60, "exp": NOW + 3600, "jti": "svc-2"}

    # A server that lets any actor through, so the chain is the only subject.
    open_as = AuthorizationServer(key, [BOOKINGS], require_may_act=False)
    hop1 = open_as.exchange(grant_type=GRANT, subject_token=user_token,
                            subject_token_type=T_ACCESS,
                            actor_token=assistant_token, actor_token_type=T_JWT,
                            audience=BOOKINGS, scope="bookings:write")
    hop2 = open_as.exchange(grant_type=GRANT,
                            subject_token=hop1["access_token"],
                            subject_token_type=T_ACCESS,
                            actor_token=mint(pricing, key),
                            actor_token_type=T_JWT, audience=BOOKINGS,
                            scope="bookings:write")
    hop3 = open_as.exchange(grant_type=GRANT,
                            subject_token=hop2["access_token"],
                            subject_token_type=T_ACCESS,
                            actor_token=mint(seats, key),
                            actor_token_type=T_JWT, audience=BOOKINGS,
                            scope="bookings:write")
    final = read(hop3["access_token"], key)

    check("the sub after three hops", "traveller-8812", final["sub"])
    check("actors in the token, current first",
          "['https://seats.exampleair.example', "
          "'https://pricing.exampleair.example', "
          "'https://assistant.exampleagent.example']",
          str(chain(final)))
    check("the booking service, reading only the current actor",
          "refused: https://seats.exampleair.example is not an allowed actor",
          bookings.call(hop3["access_token"], "bookings:write"))
    walker = ResourceServer(
        BOOKINGS, key,
        allowed_actors=[(AGENT_ISSUER,
                         "https://assistant.exampleagent.example")],
        walk_chain=True)
    check("the same service, walking the chain instead",
          "allowed, https://seats.exampleair.example for traveller-8812 "
          "on a prior actor",
          walker.call(hop3["access_token"], "bookings:write"))

    print()
    print("Part F: what the exchange does not do.")

    revoking = AuthorizationServer(key, [BOOKINGS],
                                   revoked=["user-token-1"])
    check("exchanging the user's token after it is revoked", "invalid_request",
          code_of(attempt(revoking, grant_type=GRANT,
                          subject_token=user_token,
                          subject_token_type=T_ACCESS,
                          actor_token=assistant_token, actor_token_type=T_JWT,
                          audience=BOOKINGS, scope="bookings:write")))
    check("the token issued before that, used after it",
          "allowed, https://assistant.exampleagent.example for traveller-8812",
          bookings.call(delegation["access_token"], "bookings:write"))
    # Nothing in the issued token ties it to the agent that fetched it. A
    # confirmation claim is what would (module 7); the exchange adds none.
    check("a cnf claim binding the issued token to a holder", "absent",
          "present" if "cnf" in dele else "absent")
    check("seconds that token stays usable anyway", "300",
          str(dele["exp"] - NOW))
    check("the same token once it expires", "refused: expired",
          bookings.call(delegation["access_token"], "bookings:write",
                        now=dele["exp"]))

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
