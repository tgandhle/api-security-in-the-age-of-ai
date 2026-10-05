#!/usr/bin/env python3
"""Module 37 lab: SAML assertions and where they meet APIs.

Python 3, standard library only. On Windows use `py -3` wherever the page
shows `python3`.

Nothing here opens a socket, starts a thread or a process, writes a file or
reads a clock. The identity provider, the service providers, the
authorization server, the API and the browser sessions are Python objects, a
message is a string of XML handed from one to the other, and the time is a
number the lab sets. Keys and tokens are random on every run and are never
printed. No document, message ID, assertion ID or signature value is printed
either. The output is the same bytes on every run.

Who is in it (all fictional):

  https://idp.exampleair.example        ExampleAir's identity provider (IdP)
  https://staff.exampleair.example/saml the staff portal, a service provider
                                        (SP). It exists twice: a naive build
                                        and a correct one.
  https://lunch.exampleair.example/saml the lunch-ordering site, a second and
                                        less important service provider. It
                                        accepts unsolicited responses.
  https://login.exampleair.example      the OAuth authorization server
  https://api.exampleair.example/rosters the rosters API

  Part A  an honest sign-in, and what the portal keeps from it.
  Part B  XML signature wrapping.
  Part C  unsigned and partly signed messages.
  Part D  an assertion for another service provider, and a wrong Recipient.
  Part E  replay of a bearer assertion inside its validity window.
  Part F  unsolicited responses, InResponseTo and RelayState.
  Part G  time: expired, not yet valid, and clock skew.
  Part H  trust in the wrong key.
  Part I  the document itself: a DOCTYPE, and more than one assertion.
  Part J  an assertion presented to the API.
  Part K  the correct path: session, then an access token for the API.
  Part L  nine rules the parts above pass through without isolating: one
          change each, at the service provider and at the token endpoint.

THE SIGNATURE IS A STAND-IN. This is not XML Signature.

  * Real SAML signs with XML Signature: an asymmetric key, a canonical form
    of the XML, a digest of the referenced element inside a signed
    <SignedInfo>. This lab implements none of that.
  * Here a "signature" is an HMAC-SHA256 by the identity provider over a
    fixed serialisation of ONE element: the element whose ID the
    <Reference URI="#..."> names, without that element's own <Signature>
    child. The value sits in a <Signature> element next to the reference.
  * That keeps the one property the attacks in Parts B and C turn on: a
    signature covers exactly the element it references, and says nothing
    about any other element in the same document. SAML Core section 5.4.2
    requires a single reference to the ID of the element being signed.
  * An HMAC key is shared, so in this lab a service provider could forge an
    assertion. With real SAML it holds only the public key and cannot. The
    lab's service providers never sign.
  * <KeyInfo> in a real message carries a certificate or a public key. Here
    it carries, in hex, the MAC key the attacker signed with. It stands in
    for "a key that arrived inside the message".
  * Nothing in this file is a usable SAML implementation.

Other deliberate simplifications:

  * No XML namespaces, no base64 and no HTML form. A real response travels
    base64-encoded in a form field named SAMLResponse (the HTTP POST
    binding). Here the XML text is passed directly.
  * Times are integers (seconds), not xs:dateTime values.
  * The service provider accepts exactly one assertion per response. The
    profile allows several.
  * examine() refuses an assertion whose <Conditions> has no NotOnOrAfter.
    SAML Core section 2.5.1.2 treats an omitted value as unspecified, so
    this is stricter than the standard. It also reads the <Audience>
    values of every <AudienceRestriction> as one list. The lab's identity
    provider writes one restriction with one audience.
  * The service provider reads InResponseTo and Recipient from the signed
    assertion and ignores the attributes of the <Response> element, which
    the signature on an assertion does not cover. It does not check
    Destination.
  * No encryption, no <Status>, no logout, no metadata, no artifact binding.
  * The identity provider trusts the lab for who is at the browser. Real
    user authentication is module 27.
  * The assertion addressed to the authorization server in Part K comes
    from a direct call to the identity provider. RFC 7522 leaves how the
    client obtains it out of scope, and so does this lab.
  * The token endpoint takes the assertion as XML text. RFC 7522 section 2.1
    requires base64url there. It accepts one audience value, the
    authorization server's identifier, where RFC 7522 also allows the token
    endpoint URL. It requires the client to authenticate, which RFC 7522
    leaves optional for this grant.
  * Access tokens are random handles the API looks up at the authorization
    server (introspection, module 6).

DTDs and entities: every message a party receives goes through
parse_document(), which refuses any text that contains a document type
declaration before the XML parser sees it. The one other place that parses
is own_text(), for text the lab itself produced. The lab never hands a
document type declaration to the parser, so no document it parses can
declare an entity.

Exit codes: 0 every check matched, 1 at least one did not.
"""

import copy
import hashlib
import hmac
import json
import secrets
import sys
import xml.etree.ElementTree as ET

START = 1790000000          # a fixed reference time; nothing reads a clock
SKEW = 180                  # seconds of clock skew a relying party allows
CONFIRM_WINDOW = 300        # SubjectConfirmationData NotOnOrAfter, from issue
VALIDITY = 600              # Conditions NotOnOrAfter, from issue
TOKEN_LIFETIME = 300        # access token lifetime

IDP = "https://idp.exampleair.example"
ROGUE_IDP = "https://idp.attacker.example"
PORTAL = "https://staff.exampleair.example/saml"
PORTAL_ACS = "https://staff.exampleair.example/saml/acs"
PORTAL_TEST_ACS = "https://staff-test.exampleair.example/saml/acs"
LUNCH = "https://lunch.exampleair.example/saml"
LUNCH_ACS = "https://lunch.exampleair.example/saml/acs"
AS = "https://login.exampleair.example"
TOKEN_ENDPOINT = "https://login.exampleair.example/token"
OTHER_TOKEN_ENDPOINT = "https://login.examplehotels.example/token"
ROSTERS_API = "https://api.exampleair.example/rosters"
LUNCH_API = "https://api.exampleair.example/lunch"
PAYROLL_API = "https://api.exampleair.example/payroll"
PORTAL_CLIENT = "exampleair-staff-portal"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
EVIL_URL = "https://staff.exampleair.example.attacker.example/"
DOCTYPE = "<!" + "DOCTYPE"

ROSTERS = {"alice": ["FRA-0612", "FRA-0613"], "mallory": ["LIS-0612"]}
# An account is selected by the identity provider and the NameID together.
ACCOUNTS = {(IDP, "alice"): "acct-alice", (IDP, "mallory"): "acct-mallory"}

RESULTS = []
CHECKS = 0
PARSED = [0]                # documents handed to the XML parser


def section(title):
    RESULTS.append((None, title, None))


def record(label, expected, actual):
    """Numbers are assigned here in call order. Adding a check renumbers
    every check after it, and the page cites checks by number."""
    global CHECKS
    CHECKS += 1
    RESULTS.append(("%2d. %s" % (CHECKS, label), expected, actual))


class Clock:
    def __init__(self, now):
        self.now = now


# ---------------------------------------------------------------------------
# Documents: parsing, the signature stand-in, and what an assertion says
# ---------------------------------------------------------------------------

def parse_document(text):
    """(root element, None) or (None, reason). The document type declaration
    is refused on the text, before the parser is called."""
    if not isinstance(text, str) or DOCTYPE in text:
        return None, "reject: DOCTYPE present"
    PARSED[0] += 1
    try:
        return ET.fromstring(text), None
    except ET.ParseError:
        return None, "reject: not well-formed XML"


def signed_bytes(element):
    """The fixed serialisation the stand-in signature covers: this element
    and everything inside it, without its own <Signature> child. Written as
    a loop, not a recursion."""
    out = []
    stack = [(element, False)]
    while stack:
        node, closing = stack.pop()
        if closing:
            out.append(json.dumps(["end", node.tag]))
            continue
        out.append(json.dumps(["start", node.tag, sorted(node.attrib.items()),
                               (node.text or "").strip()]))
        stack.append((node, True))
        for child in reversed(list(node)):
            if node is element and child.tag == "Signature":
                continue
            stack.append((child, False))
    return "\n".join(out).encode("utf-8")


def mac_of(element, key):
    return hmac.new(key, signed_bytes(element), hashlib.sha256).hexdigest()


def sign(element, key, key_in_message=False):
    """Adds the stand-in signature as a child of the element it covers (an
    enveloped signature), referencing that element by ID."""
    for old in element.findall("Signature"):
        element.remove(old)
    signature = ET.Element("Signature")
    ET.SubElement(signature, "Reference", {"URI": "#" + element.get("ID")})
    if key_in_message:
        ET.SubElement(signature, "KeyInfo").text = key.hex()
    ET.SubElement(signature, "SignatureValue").text = mac_of(element, key)
    element.insert(1, signature)        # after <Issuer>


def referenced(root, signature):
    """The first element in the document whose ID the signature's reference
    names, or None."""
    uri = signature.find("Reference").get("URI", "") \
        if signature.find("Reference") is not None else ""
    for node in root.iter():
        if uri == "#" + node.get("ID", "\0"):
            return node
    return None


def mac_ok(element, signature, key):
    value = signature.findtext("SignatureValue") or ""
    return element is not None and hmac.compare_digest(
        value.encode("utf-8"), mac_of(element, key).encode("utf-8"))


def covered(root, assertion, key):
    """Is THIS assertion element covered by a valid signature? Either its own
    enveloped signature, or one on the response that contains it (SAML Core
    section 5.3 calls that an inherited signature). Returns None or a
    reason. The key comes from the caller's configuration. <KeyInfo> is
    never read."""
    own = assertion.find("Signature")
    if own is not None:
        target = referenced(root, own)
        if target is not assertion:
            return "reject: the signature references another element"
        if not mac_ok(target, own, key):
            return "reject: bad signature"
        return None
    outer = root.find("Signature") if root is not assertion else None
    if outer is not None:
        target = referenced(root, outer)
        if target is not root:
            return "reject: the response signature references another element"
        if not mac_ok(target, outer, key):
            return "reject: bad signature"
        return None
    return "reject: no signature covers the assertion"


def number(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def examine(root, assertion, issuers, now):
    """The checks every relying party makes on a bearer assertion, whoever
    it is: issuer, signature, validity period, delivery window. Returns
    (None, facts) or (reason, None). `facts` is read from the element that
    was verified, and from nowhere else."""
    issuer = assertion.findtext("Issuer")
    if issuer not in issuers:
        return "reject: unknown issuer", None
    problem = covered(root, assertion, issuers.get(issuer, b""))
    if problem:
        return problem, None

    conditions = assertion.find("Conditions")
    if conditions is None:                  # then it has no expiry either
        conditions = ET.Element("Conditions")
    not_before = number(conditions.get("NotBefore"))
    not_on_or_after = number(conditions.get("NotOnOrAfter"))
    if not_before is not None and now + SKEW < not_before:
        return "reject: not yet valid", None
    if not_on_or_after is None or now >= not_on_or_after + SKEW:
        return "reject: expired", None

    data = ET.Element("SubjectConfirmationData")    # none: no window at all
    for confirmation in assertion.findall("Subject/SubjectConfirmation"):
        found = confirmation.find("SubjectConfirmationData")
        if confirmation.get("Method") == BEARER and found is not None:
            data = found
    window = number(data.get("NotOnOrAfter"))
    if window is None or now >= window + SKEW:
        return "reject: confirmation window has passed", None

    return None, {
        "id": assertion.get("ID"), "issuer": issuer,
        "name_id": assertion.findtext("Subject/NameID"),
        "audiences": [a.text for a in conditions.findall(
            "AudienceRestriction/Audience")],
        "recipient": data.get("Recipient"),
        "in_response_to": data.get("InResponseTo"),
        "window": window,
        "groups": sorted(v.text or "" for v in assertion.findall(
            "AttributeStatement/Attribute[@Name='groups']/AttributeValue"))}


class OneTimeCache:
    """Assertion IDs already used. Each is kept until `until`, the moment
    the assertion could no longer be accepted anyway."""

    def __init__(self):
        self.used = {}

    def forget_expired(self, now):
        for assertion_id in [i for i, until in self.used.items()
                             if now >= until]:
            del self.used[assertion_id]

    def first_use(self, assertion_id, until, now):
        self.forget_expired(now)
        if assertion_id in self.used:
            return False
        self.used[assertion_id] = until
        return True


# ---------------------------------------------------------------------------
# The identity provider
# ---------------------------------------------------------------------------

class IdentityProvider:
    def __init__(self, entity_id, clock):
        self.entity_id, self.clock = entity_id, clock
        self.key = secrets.token_bytes(32)
        self.clock_error = 0            # seconds this server's clock is fast
        self.validity = VALIDITY        # seconds its assertions stay valid
        self.providers = {}         # SP entity ID -> its registered ACS URLs
        self.directory = {"alice": ["crew-planning", "roster-admins"],
                          "mallory": ["cabin-crew"]}

    def register(self, entity_id, acs_urls):
        self.providers[entity_id] = list(acs_urls)

    def assertion(self, user, audience, recipient, in_response_to=None):
        now = self.clock.now + self.clock_error
        a = ET.Element("Assertion", {"ID": "_" + secrets.token_hex(16),
                                     "IssueInstant": str(now)})
        ET.SubElement(a, "Issuer").text = self.entity_id
        subject = ET.SubElement(a, "Subject")
        ET.SubElement(subject, "NameID").text = user
        confirmation = ET.SubElement(subject, "SubjectConfirmation",
                                     {"Method": BEARER})
        data = {"Recipient": recipient,
                "NotOnOrAfter": str(now + CONFIRM_WINDOW)}
        if in_response_to is not None:
            data["InResponseTo"] = in_response_to
        ET.SubElement(confirmation, "SubjectConfirmationData", data)
        conditions = ET.SubElement(a, "Conditions", {
            "NotBefore": str(now), "NotOnOrAfter": str(now + self.validity)})
        restriction = ET.SubElement(conditions, "AudienceRestriction")
        ET.SubElement(restriction, "Audience").text = audience
        ET.SubElement(a, "AuthnStatement", {"AuthnInstant": str(now)})
        statement = ET.SubElement(a, "AttributeStatement")
        groups = ET.SubElement(statement, "Attribute", {"Name": "groups"})
        for group in self.directory[user]:
            ET.SubElement(groups, "AttributeValue").text = group
        return a

    def response(self, user, audience, recipient, in_response_to=None,
                 signs="assertion"):
        now = self.clock.now + self.clock_error
        attributes = {"ID": "_" + secrets.token_hex(16),
                      "IssueInstant": str(now), "Destination": recipient}
        if in_response_to is not None:
            attributes["InResponseTo"] = in_response_to
        r = ET.Element("Response", attributes)
        ET.SubElement(r, "Issuer").text = self.entity_id
        a = self.assertion(user, audience, recipient, in_response_to)
        r.append(a)
        sign(a if signs == "assertion" else r, self.key)
        return ET.tostring(r, encoding="unicode")

    def sso(self, request_text, user, signs="assertion"):
        """The single sign-on service: an <AuthnRequest> in, a <Response>
        out. Returns (verdict, response text or None)."""
        request, problem = parse_document(request_text)
        if problem:
            return problem, None
        sp = request.findtext("Issuer")
        acs = request.get("AssertionConsumerServiceURL")
        if acs not in self.providers.get(sp, ()):
            return "refused: URL not registered for that requester", None
        return "ok", self.response(user, sp, acs, request.get("ID"), signs)

    def unsolicited(self, sp, user):
        """An IdP-initiated response: no request, so no InResponseTo. It goes
        to the service provider's default endpoint."""
        return self.response(user, sp, self.providers[sp][0])

    def assertion_for(self, user, audience, recipient):
        """A bare signed assertion for another relying party. See the
        docstring: how a client obtains one is out of scope here."""
        a = self.assertion(user, audience, recipient)
        sign(a, self.key)
        return ET.tostring(a, encoding="unicode")


# ---------------------------------------------------------------------------
# The two builds of a service provider
# ---------------------------------------------------------------------------

class ServiceProvider:
    """The correct build. `identity_providers` maps the entity ID of each
    identity provider this service provider is configured for to its key."""

    def __init__(self, entity_id, acs, identity_providers, clock,
                 allow_unsolicited=False):
        self.entity_id, self.acs = entity_id, acs
        self.identity_providers = identity_providers
        self.clock = clock
        self.allow_unsolicited = allow_unsolicited
        self.cache = OneTimeCache()

    def begin(self, session, wanted="/"):
        """Starts a sign-in in this browser session. Returns the
        <AuthnRequest> text and the RelayState value that travels with it:
        an opaque handle, not the URL the user asked for."""
        request_id = "_" + secrets.token_hex(16)
        relay_state = secrets.token_urlsafe(16)
        session["pending"] = request_id
        session["return_to"] = {relay_state: wanted}
        request = ET.Element("AuthnRequest", {
            "ID": request_id, "IssueInstant": str(self.clock.now),
            "AssertionConsumerServiceURL": self.acs})
        ET.SubElement(request, "Issuer").text = self.entity_id
        return ET.tostring(request, encoding="unicode"), relay_state

    def consume(self, session, text, delivered_to=None):
        """The assertion consumer service. `delivered_to` is the URL the
        browser posted the response to."""
        delivered_to = delivered_to or self.acs
        now = self.clock.now
        root, problem = parse_document(text)
        if problem:
            return problem
        assertions = root.findall("Assertion")
        if root.tag != "Response" or len(assertions) != 1:
            return "reject: expected exactly one assertion"
        problem, facts = examine(root, assertions[0],
                                 self.identity_providers, now)
        if problem:
            return problem

        if self.entity_id not in facts["audiences"]:
            return "reject: audience mismatch"
        if facts["recipient"] != delivered_to:
            return "reject: recipient mismatch"
        if facts["in_response_to"] is None:
            if not self.allow_unsolicited:
                return "reject: unsolicited response"
        else:
            if facts["in_response_to"] != session.get("pending"):
                return "reject: InResponseTo is not this browser's request"
            session.pop("pending", None)    # one request, one response
        if not self.cache.first_use(facts["id"], facts["window"] + SKEW,
                                    now):
            return "reject: assertion already used"

        # The service provider's own session. The assertion is not kept.
        session["sid"] = secrets.token_urlsafe(32)
        session["user"] = (facts["issuer"], facts["name_id"])
        session["groups"] = facts["groups"]
        return "accept"

    def landing(self, session, relay_state):
        """Where to send the browser after a sign-in. RelayState is looked up
        in what this session stored. It is never used as a URL."""
        return session.get("return_to", {}).get(relay_state, "/")


class NaiveServiceProvider(ServiceProvider):
    """NOT a build to copy. If a signature is present it verifies the
    element the signature references, with the key in the message if there
    is one. Then it reads the first assertion in the document. It checks
    nothing else."""

    def read(self, text):
        root, problem = parse_document(text)
        if problem:
            return problem, None
        signature = next(root.iter("Signature"), None)
        if signature is not None:
            key = self.identity_providers[IDP]
            if signature.find("KeyInfo") is not None:
                key = bytes.fromhex(signature.findtext("KeyInfo"))
            if not mac_ok(referenced(root, signature), signature, key):
                return "reject: bad signature", None
        first = next(root.iter("Assertion"), None)
        if first is None:
            return "reject: no assertion", None
        return None, first.findtext("Subject/NameID")

    def consume(self, session, text, delivered_to=None):
        problem, name_id = self.read(text)
        if problem:
            return problem
        session["user"] = (None, name_id)       # the NameID alone
        return "accept as " + str(name_id)

    def landing(self, session, relay_state):
        return relay_state                      # treated as a URL


# ---------------------------------------------------------------------------
# The authorization server and the API
# ---------------------------------------------------------------------------

class AuthorizationServer:
    """Its token endpoint takes a SAML assertion as an authorization grant,
    in the spirit of RFC 7522 section 3."""

    def __init__(self, identity_providers, clock):
        self.identity_providers, self.clock = identity_providers, clock
        self.clients = {}
        self.tokens = {}
        self.cache = OneTimeCache()

    def register(self, client_id, audiences):
        secret = secrets.token_urlsafe(32)
        self.clients[client_id] = {"secret": secret, "audiences": audiences}
        return secret

    def token(self, client_id, client_secret, assertion_text, audience):
        now = self.clock.now
        client = self.clients.get(client_id, {"secret": "", "audiences": []})
        if not client["secret"] or not hmac.compare_digest(
                client["secret"].encode("utf-8"),
                str(client_secret).encode("utf-8")):
            return {"error": "invalid_client"}
        if audience not in client["audiences"]:
            return {"error": "invalid_target"}

        def refuse(reason):
            return {"error": "invalid_grant",
                    "error_description": reason.replace("reject: ", "")}

        root, problem = parse_document(assertion_text)
        if problem:
            return refuse(problem)
        problem, facts = examine(root, root, self.identity_providers, now)
        if problem:
            return refuse(problem)
        if AS not in facts["audiences"]:
            return refuse("audience is not the authorization server")
        if facts["recipient"] != TOKEN_ENDPOINT:
            return refuse("recipient mismatch")
        if not self.cache.first_use(facts["id"], facts["window"] + SKEW,
                                    now):
            return refuse("assertion already used")

        access_token = secrets.token_urlsafe(32)
        self.tokens[access_token] = {
            "active": True, "sub": facts["name_id"], "aud": audience,
            "client_id": client_id, "exp": now + TOKEN_LIFETIME}
        return {"access_token": access_token, "token_type": "Bearer",
                "expires_in": TOKEN_LIFETIME}

    def introspect(self, token):
        info = self.tokens.get(token)
        if info is None:
            return {"active": False}
        if self.clock.now >= info["exp"]:
            return {"active": False}
        return dict(info)


class RostersApi:
    def __init__(self, authorization_server, idp_key):
        self.authorization_server = authorization_server
        self.idp_key = idp_key          # only the naive handler uses it

    def answer(self, user):
        return "200 %s: %d rosters" % (user, len(ROSTERS.get(user, [])))

    def get(self, bearer):
        """Accepts one thing: an access token the authorization server
        issued for this API."""
        info = self.authorization_server.introspect(bearer)
        if not info.get("active"):
            return "401 invalid_token"
        if info.get("aud") != ROSTERS_API:
            return "401 invalid_token: audience mismatch"
        return self.answer(info["sub"])

    def naive_get(self, bearer):
        """NOT a handler to copy: "the identity provider signed it"."""
        if bearer.lstrip().startswith("<"):
            reader = NaiveServiceProvider(None, None, {IDP: self.idp_key},
                                          None)
            problem, name_id = reader.read(bearer)
            return "401 invalid_token" if problem else self.answer(name_id)
        return self.get(bearer)


# ---------------------------------------------------------------------------
# What Mallory does to documents. She holds no identity provider key.
# ---------------------------------------------------------------------------

def own_text(text):
    """Parses text this lab produced a moment ago: a message its identity
    provider issued, or one Mallory built from such a message. It serves
    Mallory's tools and the checks that look inside a document. No party
    uses it on a message it receives. Those go through parse_document()."""
    return ET.fromstring(text)


def edit(text, change):
    """Mallory parses a message she holds, changes it, and serialises it."""
    root = own_text(text)
    change(root)
    return ET.tostring(root, encoding="unicode")


def renamed(assertion, name_id):
    """A copy of an assertion that names someone else, with a new ID."""
    forged = copy.deepcopy(assertion)
    forged.set("ID", "_" + secrets.token_hex(16))
    forged.find("Subject/NameID").text = name_id
    return forged


def wrap_assertion(root):
    """Signature wrapping. The signed assertion moves aside, intact. A copy
    that names Alice takes its place and keeps a copy of the signature,
    which still references the original by ID."""
    original = root.find("Assertion")
    position = list(root).index(original)
    root.remove(original)
    root.insert(position, renamed(original, "alice"))
    ET.SubElement(root, "Extensions").append(original)


def strip_signature(root):
    """Removes the signature and renames the subject. Nothing is signed."""
    assertion = root.find("Assertion")
    assertion.remove(assertion.find("Signature"))
    assertion.find("Subject/NameID").text = "alice"


def rename_in_place(root):
    """Edits the subject inside a signed element and changes nothing else."""
    root.find("Assertion/Subject/NameID").text = "alice"


def wrap_response(root):
    """The same trick one level up. `root` is a response the identity
    provider signed as a whole. It moves aside, intact, inside a new
    response that carries a copy of its signature and an unsigned assertion
    naming Alice."""
    original = copy.deepcopy(root)
    forged = renamed(root.find("Assertion"), "alice")
    signature = copy.deepcopy(root.find("Signature"))
    for child in list(root):
        if child.tag != "Issuer":
            root.remove(child)
    root.set("ID", "_" + secrets.token_hex(16))
    root.append(signature)
    root.append(forged)
    ET.SubElement(root, "Extensions").append(original)


def resign_with(key, issuer=None):
    """Mallory signs with a key of her own and puts that key in the
    message."""
    def change(root):
        assertion = root.find("Assertion")
        assertion.find("Subject/NameID").text = "alice"
        if issuer:
            assertion.find("Issuer").text = issuer
        sign(assertion, key, key_in_message=True)
    return change


def extend_window(root):
    """Edits one attribute inside the signed assertion: the delivery window
    now ends an hour later."""
    data = root.find("Assertion/Subject/SubjectConfirmation/"
                     "SubjectConfirmationData")
    data.set("NotOnOrAfter", str(int(data.get("NotOnOrAfter")) + 3600))


def nest_signature(root):
    """Adds an empty element named Signature inside the signed assertion,
    one level below the place where the assertion's own signature sits."""
    ET.SubElement(root.find("Assertion/AttributeStatement"), "Signature")


def rename_bare(root):
    """Renames the subject of a bare assertion. `root` is the assertion."""
    root.find("Subject/NameID").text = "alice"


def add_second_assertion(extra_text):
    def change(root):
        root.append(own_text(extra_text).find("Assertion"))
    return change


def assertion_of(text):
    """The <Assertion> element of a response, as text."""
    return ET.tostring(own_text(text).find("Assertion"),
                       encoding="unicode")


# ===========================================================================

def main():
    clock = Clock(START)
    idp = IdentityProvider(IDP, clock)
    idp.register(PORTAL, [PORTAL_ACS, PORTAL_TEST_ACS])
    idp.register(LUNCH, [LUNCH_ACS])
    trusted = {IDP: idp.key}            # stands in for the configured key
    portal = ServiceProvider(PORTAL, PORTAL_ACS, trusted, clock)
    naive = NaiveServiceProvider(PORTAL, PORTAL_ACS, trusted, clock)
    lunch = ServiceProvider(LUNCH, LUNCH_ACS, trusted, clock,
                            allow_unsolicited=True)
    authorization_server = AuthorizationServer(trusted, clock)
    portal_secret = authorization_server.register(
        PORTAL_CLIENT, [ROSTERS_API, LUNCH_API])
    api = RostersApi(authorization_server, idp.key)
    mallory_key = secrets.token_bytes(32)

    def sign_in(sp, user, change=None, delay=0, signs="assertion",
                session=None):
        """A whole SP-initiated sign-in in one browser session: the request,
        the identity provider, an optional edit by whoever holds the
        response, an optional delay, the assertion consumer service."""
        session = {} if session is None else session
        request, _ = sp.begin(session)
        _, text = idp.sso(request, user, signs)
        if change:
            text = edit(text, change)
        clock.now += delay
        verdict = sp.consume(session, text)
        clock.now -= delay
        return verdict

    print("keys and tokens are random for this run; no key, token, "
          "document or signature value is printed")

    # ---------------- Part A -------------------------------------------
    section("Part A: an honest sign-in, and what the portal keeps from it.")

    request = ET.Element("AuthnRequest", {
        "ID": "_r1", "AssertionConsumerServiceURL": EVIL_URL + "acs"})
    ET.SubElement(request, "Issuer").text = PORTAL
    record("request naming an endpoint the IdP has not registered",
           "refused: URL not registered for that requester",
           idp.sso(ET.tostring(request, encoding="unicode"), "alice")[0])
    record("honest sign-in by Alice: naive portal", "accept as alice",
           sign_in(naive, "alice"))
    alice_session = {}
    request, relay_state = portal.begin(alice_session, "/rosters/today")
    _, alice_response = idp.sso(request, "alice")
    record("  correct portal", "accept",
           portal.consume(alice_session, alice_response))
    record("  the session it creates: [account, groups, assertion kept]",
           ["acct-alice", ["crew-planning", "roster-admins"], False],
           [ACCOUNTS.get(alice_session.get("user")),
            alice_session.get("groups"),
            any("Assertion" in str(v) for v in alice_session.values())])
    record("  where the RelayState handle of that sign-in sends Alice",
           "/rosters/today", portal.landing(alice_session, relay_state))
    honest = own_text(alice_response)
    signature = honest.find("Assertion/Signature")
    record("  the element the signature references, by ID", "Assertion",
           getattr(referenced(honest, signature), "tag", None))

    # ---------------- Part B -------------------------------------------
    section("Part B: XML signature wrapping.")

    session = {}
    _, text = idp.sso(naive.begin(session)[0], "mallory")
    text = edit(text, wrap_assertion)
    record("Mallory signs in as herself and wraps the response: naive portal",
           "accept as alice", naive.consume(session, text))
    wrapped = own_text(text)
    signature = next(wrapped.iter("Signature"))
    target = referenced(wrapped, signature)
    record("  in that document: [signature verifies, over, first assertion]",
           [True, "mallory", "alice"],
           [mac_ok(target, signature, idp.key),
            target.findtext("Subject/NameID"),
            next(wrapped.iter("Assertion")).findtext("Subject/NameID")])
    record("  correct portal",
           "reject: the signature references another element",
           sign_in(portal, "mallory", wrap_assertion))

    # ---------------- Part C -------------------------------------------
    section("Part C: unsigned and partly signed messages.")

    record("signature removed, subject renamed to Alice: naive portal",
           "accept as alice", sign_in(naive, "mallory", strip_signature))
    record("  correct portal", "reject: no signature covers the assertion",
           sign_in(portal, "mallory", strip_signature))
    record("the IdP signs the response, not the assertion: correct portal",
           "accept", sign_in(portal, "alice", signs="response"))
    record("  subject renamed inside that signed response: [naive, correct]",
           ["reject: bad signature", "reject: bad signature"],
           [sign_in(naive, "mallory", rename_in_place, signs="response"),
            sign_in(portal, "mallory", rename_in_place, signs="response")])
    record("  signed response moved aside, unsigned assertion added: naive",
           "accept as alice",
           sign_in(naive, "mallory", wrap_response, signs="response"))
    record("  correct portal",
           "reject: the response signature references another element",
           sign_in(portal, "mallory", wrap_response, signs="response"))

    # ---------------- Part D -------------------------------------------
    section("Part D: an assertion for another service provider, "
            "and a wrong Recipient.")

    def from_elsewhere(sp, source, user="alice"):
        """A response issued for `source`, posted to `sp` from a browser
        session that has a sign-in of its own in progress there. Its
        InResponseTo is therefore wrong as well. The correct build reports
        the audience or the Recipient because it checks them first."""
        _, text = idp.sso(source.begin({})[0], user)
        session = {}
        sp.begin(session)
        return sp.consume(session, text)

    record("Alice's assertion for the lunch site, posted to the naive portal",
           "accept as alice", from_elsewhere(naive, lunch))
    record("  correct portal", "reject: audience mismatch",
           from_elsewhere(portal, lunch))
    portal_test = ServiceProvider(PORTAL, PORTAL_TEST_ACS, trusted, clock)
    record("issued for the portal's test endpoint, used at production: naive",
           "accept as alice", from_elsewhere(naive, portal_test))
    record("  correct portal", "reject: recipient mismatch",
           from_elsewhere(portal, portal_test))

    # ---------------- Part E -------------------------------------------
    section("Part E: replay of a bearer assertion inside its validity window.")

    replayed = idp.unsolicited(PORTAL, "alice")
    record("one response delivered twice: naive portal",
           ["accept as alice", "accept as alice"],
           [naive.consume({}, replayed), naive.consume({}, replayed)])
    replayed = idp.unsolicited(LUNCH, "alice")
    record("  a correct provider that accepts unsolicited responses",
           ["accept", "reject: assertion already used"],
           [lunch.consume({}, replayed), lunch.consume({}, replayed)])
    replayed_id = own_text(replayed).find("Assertion").get("ID")
    clock.now += 400        # past the delivery window, inside the skew
    third = lunch.consume({}, replayed)
    clock.now += 100        # 500 seconds: it can no longer be accepted
    lunch.consume({}, idp.unsolicited(LUNCH, "alice"))  # the next sign-in
    kept = replayed_id in lunch.cache.used
    clock.now -= 500
    record("  again 400 s later, inside the skew: [verdict, ID kept at 500 s]",
           ["reject: assertion already used", False], [third, kept])

    # ---------------- Part F -------------------------------------------
    section("Part F: unsolicited responses, InResponseTo and RelayState.")

    unsolicited = idp.unsolicited(PORTAL, "mallory")
    record("Mallory's unsolicited response posted from Alice's browser: naive",
           "accept as mallory", naive.consume({}, unsolicited))
    record("  correct portal, which expects InResponseTo",
           "reject: unsolicited response", portal.consume({}, unsolicited))
    _, solicited = idp.sso(portal.begin({})[0], "mallory")
    victim = {}
    portal.begin(victim)
    record("Mallory's answer to her own request, in Alice's browser: correct",
           "reject: InResponseTo is not this browser's request",
           portal.consume(victim, solicited))
    victim = {}
    request, relay_state = portal.begin(victim, "/rosters/today")
    _, text = idp.sso(request, "alice")
    naive.consume(victim, text)
    record("RelayState swapped for a look-alike URL: naive portal sends her "
           "to", EVIL_URL, naive.landing(victim, EVIL_URL))
    portal.consume(victim, text)
    record("  correct portal: [her own RelayState, the swapped one]",
           ["/rosters/today", "/"],
           [portal.landing(victim, relay_state),
            portal.landing(victim, EVIL_URL)])

    # ---------------- Part G -------------------------------------------
    section("Part G: time. The skew allowance is %d seconds." % SKEW)

    record("an assertion used two hours after it was issued: naive portal",
           "accept as alice", sign_in(naive, "alice", delay=7200))
    record("  correct portal", "reject: expired",
           sign_in(portal, "alice", delay=7200))
    record("  500 seconds after issue: still valid, but",
           "reject: confirmation window has passed",
           sign_in(portal, "alice", delay=500))
    record("  400 seconds after issue: past the window, inside the skew",
           "accept", sign_in(portal, "alice", delay=400))
    idp.clock_error = 600
    record("the IdP's clock is ten minutes fast: correct portal",
           "reject: not yet valid", sign_in(portal, "alice"))
    idp.clock_error = 60
    record("  one minute fast, inside the skew", "accept",
           sign_in(portal, "alice"))
    idp.clock_error = 0

    # ---------------- Part H -------------------------------------------
    section("Part H: trust in the wrong key.")

    record("signed by Mallory, her key inside the message: naive portal",
           "accept as alice",
           sign_in(naive, "mallory", resign_with(mallory_key)))
    record("  correct portal, which uses the key it was configured with",
           "reject: bad signature",
           sign_in(portal, "mallory", resign_with(mallory_key)))
    record("the same, issued in the name of an IdP nobody configured: naive",
           "accept as alice",
           sign_in(naive, "mallory", resign_with(mallory_key, ROGUE_IDP)))
    record("  correct portal", "reject: unknown issuer",
           sign_in(portal, "mallory", resign_with(mallory_key, ROGUE_IDP)))

    # ---------------- Part I -------------------------------------------
    section("Part I: the document itself.")

    results, parser_calls = [], 0
    for sp in (naive, portal):
        session = {}
        _, text = idp.sso(sp.begin(session)[0], "alice")
        before = PARSED[0]
        results.append(sp.consume(
            session, DOCTYPE + ' Response [<!ENTITY e "x">]>' + text))
        parser_calls += PARSED[0] - before
    record("an honest response with a DOCTYPE: [naive, correct, parser calls]",
           ["reject: DOCTYPE present", "reject: DOCTYPE present", 0],
           results + [parser_calls])
    earlier = idp.unsolicited(PORTAL, "mallory")
    record("a response that carries two assertions: correct portal",
           "reject: expected exactly one assertion",
           sign_in(portal, "mallory", add_second_assertion(earlier)))

    # ---------------- Part J -------------------------------------------
    section("Part J: an assertion presented to the API.")

    record("Alice's assertion sent to the rosters API as a bearer: naive API",
           "200 alice: 2 rosters", api.naive_get(alice_response))
    record("  the API that accepts only access tokens issued for it",
           "401 invalid_token", api.get(alice_response))

    # ---------------- Part K -------------------------------------------
    section("Part K: the correct path. Session, then an access token.")

    record("Alice has a portal session, created in Part A",
           "acct-alice", ACCOUNTS.get(alice_session.get("user")))
    refused = authorization_server.token(
        PORTAL_CLIENT, portal_secret, assertion_of(alice_response),
        ROSTERS_API)
    record("the portal offers its own sign-in assertion at the token endpoint",
           "invalid_grant: audience is not the authorization server",
           "%s: %s" % (refused.get("error"), refused.get("error_description")))
    for_as = idp.assertion_for("alice", AS, TOKEN_ENDPOINT)
    granted = authorization_server.token(PORTAL_CLIENT, portal_secret,
                                         for_as, ROSTERS_API)
    record("an assertion addressed to the authorization server",
           ["access_token", "expires_in", "token_type"], sorted(granted))
    access_token = granted.get("access_token", "")
    record("  the rosters API, given that access token",
           "200 alice: 2 rosters", api.get(access_token))
    again = authorization_server.token(PORTAL_CLIENT, portal_secret, for_as,
                                       ROSTERS_API)
    record("  the same assertion offered a second time",
           "invalid_grant: assertion already used",
           "%s: %s" % (again.get("error"), again.get("error_description")))
    record("a fresh assertion, with the wrong client secret", "invalid_client",
           authorization_server.token(
               PORTAL_CLIENT, "not the secret",
               idp.assertion_for("alice", AS, TOKEN_ENDPOINT),
               ROSTERS_API).get("error"))
    record("  for an API the portal is not registered to call",
           "invalid_target",
           authorization_server.token(
               PORTAL_CLIENT, portal_secret,
               idp.assertion_for("alice", AS, TOKEN_ENDPOINT),
               PAYROLL_API).get("error"))
    elsewhere = authorization_server.token(
        PORTAL_CLIENT, portal_secret,
        idp.assertion_for("alice", AS, OTHER_TOKEN_ENDPOINT), ROSTERS_API)
    record("  audience is this server, Recipient is another token endpoint",
           "invalid_grant: recipient mismatch",
           "%s: %s" % (elsewhere.get("error"),
                       elsewhere.get("error_description")))
    for_lunch = authorization_server.token(
        PORTAL_CLIENT, portal_secret,
        idp.assertion_for("alice", AS, TOKEN_ENDPOINT), LUNCH_API)
    record("an access token issued for the lunch API, sent to the rosters API",
           "401 invalid_token: audience mismatch",
           api.get(for_lunch.get("access_token", "")))
    clock.now += TOKEN_LIFETIME
    record("the access token, %d seconds later: introspection says active"
           % TOKEN_LIFETIME, False,
           authorization_server.introspect(access_token).get("active"))
    clock.now -= TOKEN_LIFETIME
    idp.directory["alice"].remove("roster-admins")
    record("Alice leaves roster-admins at the IdP: [IdP now, portal session]",
           [["crew-planning"], ["crew-planning", "roster-admins"]],
           [idp.directory["alice"], alice_session.get("groups")])

    # ---------------- Part L -------------------------------------------
    section("Part L: one change each, for rules not isolated above.")

    idp.validity = 200      # shorter than the delivery window of 300 s
    record("the IdP makes its assertions valid for 200 s: one used at 400 s",
           "reject: expired", sign_in(portal, "alice", delay=400))
    record("  one used at 250 s: past those 200 s, inside the skew",
           "accept", sign_in(portal, "alice", delay=250))
    idp.validity = VALIDITY
    record("a response 500 s old, its delivery window edited to end later",
           "reject: bad signature",
           sign_in(portal, "alice", extend_window, delay=500))
    record("an element named Signature added deeper in the signed assertion",
           "reject: bad signature",
           sign_in(portal, "mallory", nest_signature))
    emptied = own_text(alice_response)
    signature = emptied.find("Assertion/Signature")
    signature.find("Reference").set("URI", "#")
    record("the element a reference of \"#\", which names no ID, resolves to",
           None, getattr(referenced(emptied, signature), "tag", None))
    session = {}
    request, _ = portal.begin(session)
    _, first = idp.sso(request, "alice")
    _, second = idp.sso(request, "alice")
    record("the IdP answers one request twice, both delivered: correct portal",
           ["accept", "reject: InResponseTo is not this browser's request"],
           [portal.consume(session, first), portal.consume(session, second)])
    _, solicited = idp.sso(portal.begin({})[0], "mallory")
    victim = {}
    portal.begin(victim)
    record("as check 25, InResponseTo on the Response set to Alice's request",
           "reject: InResponseTo is not this browser's request",
           portal.consume(victim, edit(solicited, lambda root: root.set(
               "InResponseTo", victim["pending"]))))

    def grant(assertion_text):
        reply = authorization_server.token(PORTAL_CLIENT, portal_secret,
                                           assertion_text, ROSTERS_API)
        if "access_token" in reply:
            return "access token issued"
        return "%s: %s" % (reply.get("error"), reply.get("error_description"))

    record("token endpoint: Mallory's assertion with the subject renamed",
           "invalid_grant: bad signature",
           grant(edit(idp.assertion_for("mallory", AS, TOKEN_ENDPOINT),
                      rename_bare)))
    for_as = idp.assertion_for("alice", AS, TOKEN_ENDPOINT)
    used_once = grant(for_as)
    clock.now += 400        # past the delivery window, inside the skew
    used_twice = grant(for_as)
    clock.now -= 400
    record("token endpoint: one assertion used, then again 400 s later",
           ["access token issued", "invalid_grant: assertion already used"],
           [used_once, used_twice])

    width = max(len(label) for label, _, _ in RESULTS if label is not None)
    for label, expected, actual in RESULTS:
        if label is None:
            print()
            print(expected)
            continue
        print("%-*s %s" % (width + 1, label, actual))

    failures = [r for r in RESULTS if r[0] is not None and r[2] != r[1]]
    print()
    if failures:
        for label, expected, actual in failures:
            print("FAILED %s: expected %r, got %r" % (label, expected, actual))
        return 1
    print("all %d lab checks passed" % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
