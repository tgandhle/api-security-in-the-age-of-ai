#!/usr/bin/env python3
"""Module 27 lab: attacks on authentication endpoints.

Run:  python3 labs/auth_endpoints_lab.py

Python 3, standard library only. On Windows use `py -3` wherever this page
shows `python3`.

Nothing here opens a socket. The login service is a plain Python object with
login, request_reset, reset and change_email methods, the attacker is a few
loops that call them, and time is an injected clock that only moves when the
lab moves it. dee, fay and gia are given passwords from the COMMON list on
purpose, and the vulnerable service's reset tokens are a counter. Every other
password, and every session identifier, salt, one-time-code seed and reset
token of the fixed service, is random, generated at run time and never
printed, so the output is the same on every run.

  Part A  a vulnerable service. Credential stuffing, brute force, password
          spraying, three kinds of account enumeration, four reset token
          faults, an email change with a stolen session and a stolen password
          table. Every attack succeeds.
  Part B  the fixed service: throttling per account and per source, and
          uniform responses.
  Part C  what throttling does not stop: a breached password that is right on
          the first try. A second factor does.
  Part D  reset tokens that are random, single use, short-lived and bound to
          one account.
  Part E  re-authentication for an email change, and password storage.
  Part F  the legitimate user still gets in, and what an attacker can do with
          the lockout is bounded.

Deliberate simplifications, so nothing here is mistaken for production code:

  * PBKDF2_ITERATIONS is a lab value, far below any recommended setting, so
    the lab finishes quickly. The lesson page gives the published figures.
  * hashlib.pbkdf2_hmac needs a Python built with OpenSSL. Where it is
    missing (the in-browser Python this course uses is one such build), the
    lab uses the same function written with the hmac module. Check 50
    compares the two wherever both exist.
  * FixedAuth.migrate takes a plaintext password so that the fixed service
    can start with the same accounts as the vulnerable one. A real migration
    never has the plaintext: it re-hashes when the user next signs in.
  * A response is a status, a message and an optional Retry-After. Headers
    other than Retry-After are not modelled.
  * FixedAuth.request_reset returns the same answer for a known and an
    unknown address but does less work for the unknown one. A real service
    also has to make the two take the same time, for example by sending the
    message from a background job.
  * One-time codes follow the HOTP and TOTP algorithms (RFC 4226, RFC 6238)
    with HMAC-SHA-1, six digits and a 30 second step. Enrolment, recovery
    codes and clock drift handling are left out.
"""

import collections
import hashlib
import hmac
import secrets
import sys

PBKDF2_ITERATIONS = 1000     # lab value only; see the docstring
SALT_BYTES = 16
MIN_LENGTH = 15              # single-factor minimum in NIST SP 800-63B-4 sec. 3.1.1.2
ACCOUNT_FAILURES = 5         # consecutive failures before an account starts to lock
LOCK_BASE = 60               # seconds; doubles with each further failure
LOCK_CAP = 900               # seconds; no single lock is longer than this
SOURCE_FAILURES = 10         # failures one source may cause inside SOURCE_WINDOW
SOURCE_WINDOW = 600          # seconds
RESET_TTL = 900              # seconds a reset token stays valid
RESET_MAILS_PER_HOUR = 3     # reset messages one account can be sent per hour
TOTP_STEP = 30               # seconds; the default RFC 6238 recommends

# Common passwords. The first eight appear as examples in OWASP API2:2023,
# OWASP A07:2025 or NIST SP 800-63B-4. A real blocklist also holds breach
# corpuses and dictionary words.
COMMON = ["password", "123456", "qwerty", "Password1", "Password1!", "admin",
          "Winter2026", "ILoveMyDog7", "passwordpassword", "123456789012345"]
BLOCKLIST = frozenset(p.lower() for p in COMMON)
SERVICE_WORDS = ("examplehotels", "examplehotels.example")

Resp = collections.namedtuple("Resp", "status message session retry_after",
                              defaults=(None, None))

RESULTS = []
CHECKS = 0


def section(title):
    RESULTS.append((None, title, None))


def record(label, expected, actual):
    """Numbers are assigned here in call order. Adding a check renumbers
    every check after it, and the page cites checks by number."""
    global CHECKS
    CHECKS += 1
    RESULTS.append(("%2d. %s" % (CHECKS, label), expected, actual))


def show(resp):
    return "%d %s" % (resp.status, resp.message)


class Clock:
    def __init__(self):
        self.now = 1000000

    def advance(self, seconds):
        self.now += seconds


# ---------------------------------------------------------------------------
# Password hashing and one-time codes
# ---------------------------------------------------------------------------

def pbkdf2_pure(password, salt, iterations):
    """PBKDF2 with HMAC-SHA-256, one 32 byte block, using only hmac."""
    keyed = hmac.new(password, digestmod="sha256")

    def prf(message):
        h = keyed.copy()
        h.update(message)
        return h.digest()

    block = prf(salt + b"\x00\x00\x00\x01")
    total = int.from_bytes(block, "big")
    for _ in range(iterations - 1):
        block = prf(block)
        total ^= int.from_bytes(block, "big")
    return total.to_bytes(32, "big")


def slow_hash(password, salt, iterations=PBKDF2_ITERATIONS):
    if hasattr(hashlib, "pbkdf2_hmac"):
        return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return pbkdf2_pure(password.encode(), salt, iterations)


def fast_hash(password):
    """What the vulnerable service stores: one unsalted SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def truncate(mac, digits=6):
    """Dynamic truncation, RFC 4226 section 5.3."""
    offset = mac[-1] & 0x0F
    number = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
    return "%0*d" % (digits, number % 10 ** digits)


def totp(seed, now, step_offset=0):
    """RFC 6238 section 4.2: HOTP over the number of time steps since 0."""
    counter = now // TOTP_STEP + step_offset
    return truncate(hmac.new(seed, counter.to_bytes(8, "big"), "sha1").digest())


def password_problem(password, email):
    """None if the password may be set, otherwise the reason it may not."""
    whole = password.lower()
    context = SERVICE_WORDS + (email.lower(), email.lower().split("@")[0])
    if whole in BLOCKLIST or whole in context:
        return "password is on the blocklist of common or expected values"
    if len(password) < MIN_LENGTH:
        return "password is shorter than %d characters" % MIN_LENGTH
    return None


# ---------------------------------------------------------------------------
# The vulnerable service
# ---------------------------------------------------------------------------

class VulnerableAuth:
    def __init__(self, clock):
        self.clock = clock
        self.users = {}          # email -> unsalted SHA-256 of the password
        self.sessions = {}       # session id -> email
        self.outbox = collections.defaultdict(list)   # email -> reset tokens mailed
        self.tokens = set()      # every token ever issued, for anyone, forever
        self.next_token = 100000
        self.hash_calls = 0

    def register(self, email, password):
        self.users[email] = fast_hash(password)

    def login(self, email, password, source=None):
        if email not in self.users:
            return Resp(404, "no such account")
        self.hash_calls += 1
        if self.users[email] != fast_hash(password):
            return Resp(401, "wrong password")
        sid = secrets.token_urlsafe(32)
        self.sessions[sid] = email
        return Resp(200, "welcome", session=sid)

    def request_reset(self, email, source=None):
        if email not in self.users:
            return Resp(404, "no account uses that address")
        token = "%06d" % self.next_token      # a counter: the next one is predictable
        self.next_token += 1
        self.tokens.add(token)
        self.outbox[email].append(token)
        return Resp(200, "reset link sent")

    def reset(self, email, token, new_password, source=None):
        if email not in self.users or token not in self.tokens:
            return Resp(401, "bad reset link")
        self.users[email] = fast_hash(new_password)   # not bound, not expired, not used up
        return Resp(200, "password changed")

    def change_email(self, session, new_email, current_password=None, source=None):
        email = self.sessions.get(session)
        if email is None:
            return Resp(401, "sign in first")
        self.users[new_email] = self.users.pop(email)  # the session alone is enough
        self.sessions[session] = new_email
        return Resp(200, "email changed")


# ---------------------------------------------------------------------------
# The fixed service
# ---------------------------------------------------------------------------

class FixedAuth:
    FAILED = Resp(401, "invalid credentials")
    RESET_SENT = Resp(200, "if that address has an account, a reset message was sent")

    def __init__(self, clock):
        self.clock = clock
        self.users = {}          # email -> {"salt", "hash", "seed", "last_step"}
        self.sessions = {}
        self.outbox = collections.defaultdict(list)
        self.notices = collections.defaultdict(list)   # email -> messages to the owner
        self.reset_tokens = {}   # SHA-256 of token -> {"email", "expires"}
        self.reset_sent = collections.defaultdict(list)  # email -> times a message went out
        self.by_account = {}     # submitted username -> {"fails", "until"}
        self.by_source = {}      # source -> times of recent failures
        self.locks = []          # every lock duration issued, in seconds
        self.hash_calls = 0
        # Verified against when the username is unknown, so that an unknown
        # account costs the same hash as a known one.
        self.dummy = self._record(secrets.token_urlsafe(24))

    # -- storage ----------------------------------------------------------
    def _record(self, password):
        salt = secrets.token_bytes(SALT_BYTES)
        self.hash_calls += 1
        return {"salt": salt, "hash": slow_hash(password, salt), "seed": None, "last_step": -1}

    def _verify(self, rec, password):
        self.hash_calls += 1
        return hmac.compare_digest(rec["hash"], slow_hash(password, rec["salt"]))

    def migrate(self, email, password):
        """An account that existed before the password policy did."""
        self.users[email] = self._record(password)

    def register(self, email, password):
        problem = password_problem(password, email)
        if problem:
            return Resp(400, problem)
        self.users[email] = self._record(password)
        return Resp(200, "account created")

    def enrol_totp(self, email):
        self.users[email]["seed"] = secrets.token_bytes(20)
        return self.users[email]["seed"]      # in real life: shown once, as a QR code

    # -- throttling -------------------------------------------------------
    def _throttled(self, account, source):
        now = self.clock.now
        recent = [t for t in self.by_source.get(source, []) if now - t < SOURCE_WINDOW]
        self.by_source[source] = recent
        if len(recent) >= SOURCE_FAILURES:
            return Resp(429, "too many attempts", retry_after=recent[0] + SOURCE_WINDOW - now)
        state = self.by_account.get(account)
        if state and now < state["until"]:
            return Resp(429, "too many attempts", retry_after=state["until"] - now)
        return None

    def _failure(self, account, source):
        self.by_source.setdefault(source, []).append(self.clock.now)
        if account is None:
            return
        state = self.by_account.setdefault(account, {"fails": 0, "until": 0})
        state["fails"] += 1
        if state["fails"] >= ACCOUNT_FAILURES:
            lock = min(LOCK_BASE * 2 ** (state["fails"] - ACCOUNT_FAILURES), LOCK_CAP)
            state["until"] = self.clock.now + lock
            self.locks.append(lock)

    # -- endpoints --------------------------------------------------------
    def login(self, email, password, source, code=None):
        blocked = self._throttled(email, source)
        if blocked:
            return blocked                     # refused before any hash is computed
        user = self.users.get(email)
        ok = self._verify(user or self.dummy, password) and user is not None
        if ok and user["seed"] is not None and not self._code_ok(user, code):
            ok = False
            self.notices[email].append("your password was right but the code was not")
        if not ok:
            self._failure(email, source)
            return self.FAILED
        self.by_account.pop(email, None)       # success clears the failure count
        sid = secrets.token_urlsafe(32)
        self.sessions[sid] = email
        return Resp(200, "welcome", session=sid)

    def _code_ok(self, user, code):
        step = self.clock.now // TOTP_STEP
        for offset in (0, -1):                 # this step, or the one before it
            if code is not None and step + offset > user["last_step"] and \
                    hmac.compare_digest(code, totp(user["seed"], self.clock.now, offset)):
                user["last_step"] = step + offset   # a code is accepted once
                return True
        return False

    def request_reset(self, email, source):
        now = self.clock.now
        sent = [t for t in self.reset_sent[email] if now - t < 3600]
        if email in self.users and len(sent) < RESET_MAILS_PER_HOUR:
            token = secrets.token_urlsafe(32)
            for key in [k for k, v in self.reset_tokens.items() if v["email"] == email]:
                del self.reset_tokens[key]     # a new token replaces the old one
            digest = hashlib.sha256(token.encode()).hexdigest()
            self.reset_tokens[digest] = {"email": email, "expires": now + RESET_TTL}
            self.reset_sent[email] = sent + [now]
            self.outbox[email].append(token)
        return self.RESET_SENT                 # the same answer either way

    def reset(self, email, token, new_password, source):
        blocked = self._throttled(None, source)    # by source only: a reset attack
        if blocked:                                # must not lock the account
            return blocked
        digest = hashlib.sha256(str(token).encode()).hexdigest()
        entry = self.reset_tokens.get(digest)
        if entry is None or entry["email"] != email or self.clock.now >= entry["expires"]:
            self._failure(None, source)
            return Resp(401, "invalid or expired reset link")
        problem = password_problem(new_password, email)
        if problem:
            return Resp(400, problem)          # the token is kept for another try
        del self.reset_tokens[digest]          # single use
        seed = self.users[email]["seed"]
        self.users[email] = self._record(new_password)
        self.users[email]["seed"] = seed
        for sid in [s for s, owner in self.sessions.items() if owner == email]:
            del self.sessions[sid]             # sessions opened with the old password end
        self.by_account.pop(email, None)
        self.notices[email].append("your password was reset")
        return Resp(200, "password changed, sign in to continue")

    def change_email(self, session, new_email, current_password, source):
        email = self.sessions.get(session)
        if email is None:
            return Resp(401, "sign in first")
        blocked = self._throttled(email, source)
        if blocked:
            return blocked
        if current_password is None or not self._verify(self.users[email], current_password):
            self._failure(email, source)
            return self.FAILED
        self.users[new_email] = self.users.pop(email)
        self.sessions[session] = new_email
        self.notices[email].append("your sign-in address was changed to " + new_email)
        return Resp(200, "email changed")


# ---------------------------------------------------------------------------
# The attacker's tools
# ---------------------------------------------------------------------------

def stuff(service, pairs, sources):
    """Replay breached (email, password) pairs. Returns statuses and the
    accounts that opened."""
    statuses, opened = [], []
    for (email, password), source in zip(pairs, sources):
        resp = service.login(email, password, source)
        statuses.append(resp.status)
        if resp.status == 200:
            opened.append(email.split("@")[0])
    return statuses, opened


def tally(statuses):
    return ", ".join("%d x %d" % (statuses.count(s), s) for s in sorted(set(statuses)))


def crack(stored, candidates):
    """One pass over a stolen table: hash each candidate once, look it up."""
    table = {fast_hash(c): c for c in candidates}
    return sorted(name.split("@")[0] for name, value in stored.items() if value in table)


def main():
    global CHECKS
    RESULTS.clear()
    CHECKS = 0
    print("accounts use the reserved .example domain; no request leaves this process")

    ana, ben, chen, dee, fay, mal = ("%s@guest.example" % n for n in
                                     ("ana", "ben", "chen", "dee", "fay", "mal"))
    people = [ana, ben, chen, dee, fay]
    pw = {who: secrets.token_urlsafe(12) for who in (ana, ben, chen, mal)}
    pw[dee], pw[fay] = "ILoveMyDog7", "Password1!"
    attacker, owner = "198.51.100.7", "192.0.2.10"
    many = ["203.0.113.%d" % (i % 250 + 1) for i in range(4000)]   # 250 source addresses in rotation

    # The breach of another site. ana and ben reused their password there.
    elsewhere = [("user%02d@elsewhere.example" % i, secrets.token_urlsafe(9)) for i in range(17)]
    breached = [(ana, pw[ana])] + elsewhere[:13] + [(ben, pw[ben])] + \
               [(chen, secrets.token_urlsafe(9))] + elsewhere[13:]
    guesses = ["password", "123456", "qwerty", "Password1", "admin", "Winter2026",
               "passwordpassword", "ILoveMyDog7", "123456789012345", "Password1!", "letmein"]
    spray = [(who, word) for word in ("123456", "qwerty", "Password1!") for who in people]

    def vulnerable():
        service = VulnerableAuth(Clock())
        for who in people + [mal]:
            service.register(who, pw[who])
        return service

    def fixed():
        service = FixedAuth(Clock())
        for who in people + [mal]:
            service.migrate(who, pw[who])
        return service

    # ------------------------------------------------------------------ A
    section("Part A: the vulnerable service. Every attack succeeds.")
    v = vulnerable()
    statuses, opened = stuff(v, breached, [attacker] * len(breached))
    record("credential stuffing, 20 breached pairs: accounts opened", ["ana", "ben"], opened)
    record("  answers to those 20 attempts", "2 x 200, 1 x 401, 17 x 404", tally(statuses))
    record("enumeration by login message: unknown, then wrong password",
           ["404 no such account", "401 wrong password"],
           [show(v.login("nobody@guest.example", "x")), show(v.login(chen, "x"))])
    record("enumeration by reset: unknown, then known address",
           ["404 no account uses that address", "200 reset link sent"],
           [show(v.request_reset("nobody@guest.example")), show(v.request_reset(chen))])
    before = v.hash_calls
    v.login("nobody@guest.example", "x")
    unknown_cost = v.hash_calls - before
    v.login(chen, "x")
    record("enumeration by work: hashes computed for unknown, known", [0, 1],
           [unknown_cost, v.hash_calls - before - unknown_cost])
    found = [i for i, word in enumerate(guesses, 1) if v.login(dee, word).status == 200]
    record("brute force on dee, 11 guesses: the guess that worked", [8], found)
    record("password spraying, 3 passwords over 5 accounts: opened", ["fay"],
           [who.split("@")[0] for who, word in spray if v.login(who, word).status == 200])

    v = vulnerable()
    v.request_reset(mal)                       # the attacker's own account
    mine = v.outbox[mal][-1]
    v.request_reset(chen)                      # then the victim's
    guess = "%06d" % (int(mine) + 1)
    stolen_pw = secrets.token_urlsafe(12)
    record("reset token guessed as the attacker's own plus one",
           "200 password changed", show(v.reset(chen, guess, stolen_pw)))
    record("  the attacker then signs in as chen", 200, v.login(chen, stolen_pw).status)
    record("reset token issued to mal, used on ana's account",
           "200 password changed", show(v.reset(ana, mine, stolen_pw)))
    record("the same token used a second time",
           "200 password changed", show(v.reset(ana, mine, stolen_pw)))
    v.clock.advance(30 * 86400)
    record("  and again 30 days later",
           "200 password changed", show(v.reset(ana, mine, stolen_pw)))

    v = vulnerable()
    session = v.login(ben, pw[ben]).session        # ben signs in; the session is stolen
    record("email changed with a stolen session and no password",
           "200 email changed", show(v.change_email(session, "mal@attacker.example")))
    v.request_reset("mal@attacker.example")
    v.reset("mal@attacker.example", v.outbox["mal@attacker.example"][-1], stolen_pw)
    record("  ben's account now opens for the attacker; ben gets",
           [200, "404 no such account"],
           [v.login("mal@attacker.example", stolen_pw).status, show(v.login(ben, pw[ben]))])
    v.register("gia@guest.example", "Password1!")
    record("stored hashes of fay and gia, who share a password, are equal", True,
           v.users[fay] == v.users["gia@guest.example"])
    record("stolen table, one pass of 11 candidates: accounts cracked",
           ["dee", "fay", "gia"], crack(v.users, guesses))

    # ------------------------------------------------------------------ B
    section("Part B: the fixed service. Throttling and uniform responses.")
    f = fixed()
    before = f.hash_calls
    answers = [f.login(dee, word, attacker) for word in guesses]
    record("brute force on dee, 11 guesses: answers", "5 x 401, 6 x 429",
           tally([a.status for a in answers]))
    record("  Retry-After on the first refusal, seconds", 60, answers[5].retry_after)
    record("  password hashes computed for the 11 guesses", 5, f.hash_calls - before)
    f = fixed()
    answers = [f.login(who, word, attacker) for who, word in spray]
    record("password spraying from one source: answers", "10 x 401, 5 x 429",
           tally([a.status for a in answers]))
    record("  accounts locked while it ran", 0, len(f.locks))
    f = fixed()
    record("login answers: unknown, then wrong password",
           ["401 invalid credentials", "401 invalid credentials"],
           [show(f.login("nobody@guest.example", "x", owner)), show(f.login(chen, "x", owner))])
    record("reset answers for unknown and known address are equal", True,
           f.request_reset("nobody@guest.example", owner) == f.request_reset(chen, owner))
    before = f.hash_calls
    f.login("nobody@guest.example", "x", owner)
    unknown_cost = f.hash_calls - before
    f.login(chen, "x", owner)
    record("hashes computed for unknown, known", [1, 1],
           [unknown_cost, f.hash_calls - before - unknown_cost])
    f = fixed()
    record("six wrong guesses: unknown and known account answer alike", True,
           [f.login("nobody@guest.example", "x", s).status for s in many[:6]] ==
           [f.login(chen, "x", s).status for s in many[6:12]] == [401] * 5 + [429])

    # ------------------------------------------------------------------ C
    section("Part C: what throttling does not stop.")
    f = fixed()
    seed = f.enrol_totp(ben)
    statuses, opened = stuff(f, breached, [attacker] * len(breached))
    record("credential stuffing from one source: answers", "1 x 200, 10 x 401, 9 x 429",
           tally(statuses))
    record("  accounts opened", ["ana"], opened)
    f = fixed()
    seed = f.enrol_totp(ben)
    statuses, opened = stuff(f, breached, many)
    record("the same list, each pair from a different source: answers", "1 x 200, 19 x 401",
           tally(statuses))
    record("  accounts opened (ben has a second factor)", ["ana"], opened)
    record("  messages waiting for ben", ["your password was right but the code was not"],
           list(f.notices[ben]))
    code = totp(seed, f.clock.now)
    record("ben, with his password and the current code", 200,
           f.login(ben, pw[ben], owner, code).status)
    record("  the same code presented again", 401,
           f.login(ben, pw[ben], owner, code).status)
    record("truncation of the example in RFC 4226 section 5.4", "872921",
           truncate(bytes.fromhex("1f8698690e02ca16618550ef7f19da8e945b555a")))

    # ------------------------------------------------------------------ D
    section("Part D: reset tokens.")
    f = fixed()
    f.request_reset(mal, attacker)
    f.request_reset(chen, owner)
    answers = [f.reset(chen, "%06d" % n, stolen_pw, attacker) for n in range(100000, 101000)]
    record("1000 counter-style guesses at chen's token: answers", "10 x 401, 990 x 429",
           tally([a.status for a in answers]))
    f.clock.advance(SOURCE_WINDOW)
    record("mal's own valid token, used on chen's account",
           "401 invalid or expired reset link", show(f.reset(chen, f.outbox[mal][-1], stolen_pw, attacker)))
    token, new_pw = f.outbox[chen][-1], secrets.token_urlsafe(12)
    session = f.login(chen, pw[chen], owner).session
    record("chen's token, with a blocklisted new password",
           "400 password is on the blocklist of common or expected values",
           show(f.reset(chen, token, "PasswordPassword", owner)))
    record("  and with a short one", "400 password is shorter than 15 characters",
           show(f.reset(chen, token, "x9!kQ2", owner)))
    record("  and with a long random one", "200 password changed, sign in to continue",
           show(f.reset(chen, token, new_pw, owner)))
    record("the same token used a second time", "401 invalid or expired reset link",
           show(f.reset(chen, token, stolen_pw, owner)))
    record("chen's earlier session after the reset", "401 sign in first",
           show(f.change_email(session, "c2@guest.example", new_pw, owner)))
    f.request_reset(ana, owner)
    f.clock.advance(900)
    record("ana's token, 900 seconds after it was issued",
           "401 invalid or expired reset link", show(f.reset(ana, f.outbox[ana][-1], new_pw, owner)))
    for _ in range(10):
        f.request_reset(dee, attacker)
    record("ten reset requests for dee in a row: messages sent", 3,
           len(f.outbox[dee]))

    # ------------------------------------------------------------------ E
    section("Part E: re-authentication and password storage.")
    f = fixed()
    session = f.login(ben, pw[ben], owner).session
    record("email change with a stolen session and no password", "401 invalid credentials",
           show(f.change_email(session, "mal@attacker.example", None, attacker)))
    record("  with the session and the current password", "200 email changed",
           show(f.change_email(session, "ben@work.example", pw[ben], owner)))
    record("  messages waiting at ben's old address",
           ["your sign-in address was changed to ben@work.example"], f.notices[ben])
    record("registering with Password1!",
           "400 password is on the blocklist of common or expected values",
           show(f.register("gia@guest.example", "Password1!")))
    record("registering with the service's own name as the password",
           "400 password is on the blocklist of common or expected values",
           show(f.register("gia@guest.example", "ExampleHotels")))
    shared = secrets.token_urlsafe(12)
    f.register("gia@guest.example", shared)
    f.register("hal@guest.example", shared)
    record("stored hashes of gia and hal, who share a password, are equal", False,
           f.users["gia@guest.example"]["hash"] == f.users["hal@guest.example"]["hash"])
    record("stolen table, the same one pass of 11 candidates: cracked", [],
           crack({who: rec["hash"].hex() for who, rec in f.users.items()}, guesses))
    salt = b"lab salt, 16 byt"
    record("pure-Python PBKDF2 equals hashlib.pbkdf2_hmac where that exists", True,
           not hasattr(hashlib, "pbkdf2_hmac") or pbkdf2_pure(b"lab input", salt, 1000) ==
           hashlib.pbkdf2_hmac("sha256", b"lab input", salt, 1000))

    # ------------------------------------------------------------------ F
    section("Part F: the legitimate user, and the cost of lockout.")
    f = fixed()
    record("chen signs in with her own password", 200, f.login(chen, pw[chen], owner).status)
    for s in many[:ACCOUNT_FAILURES]:
        f.login(chen, "x", s)
    locked = f.login(chen, pw[chen], owner)
    record("after five wrong guesses by someone else, chen gets",
           "429 too many attempts", show(locked))
    f.clock.advance(locked.retry_after or 0)
    record("  and once Retry-After has passed", 200, f.login(chen, pw[chen], owner).status)
    record("  failures still counted against chen after that", 0,
           f.by_account.get(chen, {"fails": 0})["fails"])
    f = fixed()
    before = f.hash_calls
    for second in range(3600):                 # one wrong guess a second for an hour
        f.login(chen, "x", many[second])
        f.clock.advance(1)
    record("one guess a second for an hour, 3600 sent: guesses tested", 11, f.hash_calls - before)
    record("  longest single lock, seconds", 900, max(f.locks, default=0))
    f.request_reset(chen, owner)
    new_pw = secrets.token_urlsafe(12)
    record("chen, still locked out, resets her password",
           "200 password changed, sign in to continue",
           show(f.reset(chen, f.outbox[chen][-1], new_pw, owner)))
    record("  and signs in at once with the new one", 200, f.login(chen, new_pw, owner).status)

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
