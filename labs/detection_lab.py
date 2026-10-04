#!/usr/bin/env python3
"""Module 30 lab: logging, detection and response.

Python 3, standard library only. On Windows use `py -3` wherever the page
shows `python3`.

Every other lab in this course stops an attack. This one is about the attack
that the control refused and nobody noticed, and about being able to say
afterwards what happened.

Nothing here opens a socket, starts a thread, writes a file or reads the wall
clock. The API, the two loggers, the log reader and the detection rules are
plain Python objects. Time is an integer number of seconds held by a Clock
object that the scenarios advance by hand, so the output is the same bytes on
every run.

The running example is the booking service from the module 9 lab: ExampleAir,
the same five bookings, acct-77 as the caller who walks identifiers and
acct-91 as an ordinary customer. Company names are fictional. The ownership
check from module 9 is in place throughout: the attacker is refused. The
question in this lab is whether anyone can tell.

  Part A  a log that records successes only, and a walk of 40 booking ids
          that leaves nothing in it.
  Part B  one structured event per decision, failures included, and three
          detection rules that read the log back.
  Part C  log injection: a user name with a line break forges an entry in a
          plain text log, and cannot in a log of one JSON object per line.
  Part D  what never to write: an allowlist of fields, and its limit.
  Part E  the limits of the rules: a slow walk, a split walk, a false
          positive, and two hosts whose clocks disagree.
  Part F  Option: a hash chain over the log lines, and what it cannot show.

Event names. The security events use the names in the OWASP Logging
Vocabulary Cheat Sheet: authz_fail, authn_login_success, authn_login_fail and
input_validation_fail, at the levels it gives (CRITICAL, INFO, WARN, WARN).
The vocabulary writes an event and its parameters as one string, for example
"authz_fail:joebob1,resource". This lab keeps the name in "event" and puts
the parameters in fields of their own, so a comma or a colon inside a value
cannot change what the event says. booking_read and booking_cancel are this
lab's own names for two business events. The nearest names in the vocabulary
are sensitive_read and sensitive_delete, which it defines for data marked as
sensitive.

Deliberate simplifications:

  * The log is a string in memory, read back by splitting it into lines. A
    real log goes to a file or a collector.
  * A rule reads the whole log each time it runs. A real detector reads a
    stream.
  * A rule raises at most one alert per key. A real one would raise again
    after a quiet period.
  * A user name stands in for the user identity. Passwords and tokens are
    values made at runtime with `secrets`, held in memory and never printed.

Exit codes: 0 every check matched, 1 at least one did not.
"""

import datetime
import hashlib
import json
import re
import secrets
import sys

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


# ---------------------------------------------------------------------------
# Time. Scenarios advance a Clock by hand. A timestamp is the clock's integer
# added to a fixed starting instant, written in ISO 8601 with a UTC offset.
# ---------------------------------------------------------------------------

EPOCH = datetime.datetime(2026, 10, 4, 9, 0, 0, tzinfo=datetime.timezone.utc)


class Clock:
    def __init__(self, start=0):
        self.now = start

    def advance(self, seconds):
        self.now += seconds


def stamp(seconds):
    moment = EPOCH + datetime.timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S+00:00")


def seconds_of(timestamp):
    """The inverse of stamp(). None if the text is not a timestamp."""
    try:
        moment = datetime.datetime.fromisoformat(timestamp)
    except (TypeError, ValueError):
        return None
    if moment.tzinfo is None:
        return None
    return int((moment - EPOCH).total_seconds())


# ---------------------------------------------------------------------------
# Two loggers with the same emit() call, so the API below does not know which
# one it has.
# ---------------------------------------------------------------------------

class PlainLogger:
    """Free text, one line per event: timestamp, level, event, name=value.

    Every value is pasted into the line as it arrived. That is the defect
    Parts C and D use. successes_only=True is the defect Part A uses.
    """

    def __init__(self, clock, successes_only=False):
        self.clock = clock
        self.successes_only = successes_only
        self.text = ""

    def emit(self, event, level, **fields):
        if self.successes_only and fields.get("result") != "success":
            return
        pairs = " ".join("%s=%s" % (name, fields[name])
                         for name in sorted(fields))
        self.text += "%s %s %s %s\n" % (stamp(self.clock.now), level, event,
                                        pairs)

    def lines(self):
        return self.text.splitlines()

    def events(self):
        return [e for e in (parse_plain(line) for line in self.lines())
                if e is not None]


def parse_plain(line):
    """What a script reading the plain log does: split on spaces."""
    parts = line.split(" ")
    if len(parts) < 3 or seconds_of(parts[0]) is None:
        return None
    event = {"datetime": parts[0], "level": parts[1], "event": parts[2]}
    for pair in parts[3:]:
        name, sep, value = pair.partition("=")
        if sep:
            event[name] = value
    return event


# The only field names the structured logger will write. Anything else an
# application passes is dropped, whatever it holds.
ALLOWED_FIELDS = ("userid", "source_ip", "route", "resource", "result",
                  "reason", "request_id", "host")


class JsonLogger:
    """One JSON object per line. json.dumps escapes a line break inside a
    value as the two characters backslash and n, so a value cannot end the
    line it is written on."""

    def __init__(self, clock, appid="exampleair.bookings"):
        self.clock = clock
        self.appid = appid
        self.text = ""
        self.dropped = set()

    def emit(self, event, level, **fields):
        entry = {"datetime": stamp(self.clock.now), "appid": self.appid,
                 "event": event, "level": level}
        for name in sorted(fields):
            if name in ALLOWED_FIELDS:
                entry[name] = fields[name]
            else:
                self.dropped.add(name)
        self.text += json.dumps(entry, sort_keys=True) + "\n"

    def lines(self):
        return self.text.splitlines()

    def events(self):
        return parse_json_lines(self.lines())


def parse_json_lines(lines):
    """Reads the log back. A line that is not a JSON object is not an event."""
    events = []
    for line in lines:
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict):
            events.append(entry)
    return events


# ---------------------------------------------------------------------------
# The API. The module 9 bookings, plus twelve owned by a travel agency
# account so Part B has a business flow to watch.
# ---------------------------------------------------------------------------

def fresh_bookings():
    store = {
        "bkg-1001": dict(owner="acct-77", route="DFW-LHR", status="confirmed"),
        "bkg-1002": dict(owner="acct-91", route="SFO-NRT", status="confirmed"),
        "bkg-1003": dict(owner="acct-77", route="DFW-AMS", status="confirmed"),
        "bkg-1004": dict(owner="acct-91", route="LHR-JFK", status="confirmed"),
        "bkg-1005": dict(owner="acct-12", route="AMS-SIN", status="confirmed"),
    }
    for n in range(2001, 2013):
        store["bkg-%d" % n] = dict(owner="acct-agency", route="DFW-LHR",
                                   status="confirmed")
    return store


BOOKING_ID = re.compile(r"bkg-[0-9]{4}")


class BookingAPI:
    def __init__(self, clock, logger, passwords=None, validate_ids=False,
                 host="api-1"):
        self.clock = clock
        self.log = logger
        self.store = fresh_bookings()
        self.passwords = passwords or {}
        self.validate_ids = validate_ids
        self.host = host
        self.requests = 0

    def _request_id(self):
        self.requests += 1
        return "%s-req-%04d" % (self.host, self.requests)

    def login(self, username, password, source):
        request_id = self._request_id()
        expected = self.passwords.get(username)
        if expected is not None and secrets.compare_digest(expected, password):
            self.log.emit("authn_login_success", "INFO", userid=username,
                          source_ip=source, route="POST /login",
                          result="success", request_id=request_id,
                          host=self.host)
            return "200 signed in"
        # A developer added password= while debugging and it was never
        # removed. Part D is about what each logger does with it.
        self.log.emit("authn_login_fail", "WARN", userid=username,
                      source_ip=source, route="POST /login", result="fail",
                      reason="bad_credentials", request_id=request_id,
                      host=self.host, password=password)
        return "401 unauthorized"

    def _find(self, caller, booking_id, source, route):
        """The module 9 check, with one event for each way it can refuse.
        Returns the booking, or None after logging why."""
        request_id = self._request_id()
        if self.validate_ids and not BOOKING_ID.fullmatch(booking_id):
            # The name of the field that failed, never the value it held.
            self.log.emit("input_validation_fail", "WARN", userid=caller,
                          source_ip=source, route=route, result="fail",
                          reason="booking_id", request_id=request_id,
                          host=self.host)
            return None, request_id
        booking = self.store.get(booking_id)
        if booking is None or booking["owner"] != caller:
            # The response is the same 404 for both. The log is the one
            # place that keeps the difference.
            reason = "unknown_id" if booking is None else "not_owner"
            self.log.emit("authz_fail", "CRITICAL", userid=caller,
                          source_ip=source, route=route, resource=booking_id,
                          result="fail", reason=reason, request_id=request_id,
                          host=self.host)
            return None, request_id
        return booking, request_id

    def get_booking(self, caller, booking_id, source):
        route = "GET /bookings/{id}"
        booking, request_id = self._find(caller, booking_id, source, route)
        if booking is None:
            return "404 not found"
        self.log.emit("booking_read", "INFO", userid=caller, source_ip=source,
                      route=route, resource=booking_id, result="success",
                      request_id=request_id, host=self.host)
        return "200 %s" % booking["route"]

    def cancel_booking(self, caller, booking_id, source):
        route = "DELETE /bookings/{id}"
        booking, request_id = self._find(caller, booking_id, source, route)
        if booking is None:
            return "404 not found"
        booking["status"] = "cancelled"
        self.log.emit("booking_cancel", "INFO", userid=caller,
                      source_ip=source, route=route, resource=booking_id,
                      result="success", request_id=request_id, host=self.host)
        return "200 cancelled"


# ---------------------------------------------------------------------------
# Detection rules. Each one reads events that were parsed back out of the
# log, never the API's own state.
# ---------------------------------------------------------------------------

def in_time_order(events):
    """What a collector does before a rule sees events from several hosts."""
    return sorted((e for e in events if seconds_of(e.get("datetime")) is not None),
                  key=lambda e: seconds_of(e["datetime"]))


def rule_count(events, event, key, threshold, window):
    """Alert the first time `threshold` events named `event` that share one
    value of `key` fall inside `window` seconds. One alert per key."""
    alerts, recent, fired = [], {}, set()
    for e in in_time_order(events):
        if e.get("event") != event or e.get(key) is None:
            continue
        now = seconds_of(e["datetime"])
        times = recent.setdefault(e[key], [])
        times.append(now)
        while times[0] <= now - window:
            times.pop(0)
        if len(times) >= threshold and e[key] not in fired:
            fired.add(e[key])
            alerts.append({"key": e[key], "at": e["datetime"],
                           "count": len(times)})
    return alerts


def rule_distinct(events, event, group, distinct, threshold, window):
    """Alert the first time events named `event` that share one value of
    `group` carry `threshold` different values of `distinct` inside `window`
    seconds. One alert per group."""
    alerts, recent, fired = [], {}, set()
    for e in in_time_order(events):
        if e.get("event") != event or e.get(group) is None \
                or e.get(distinct) is None:
            continue
        now = seconds_of(e["datetime"])
        seen = recent.setdefault(e[group], [])
        seen.append((now, e[distinct]))
        while seen[0][0] <= now - window:
            seen.pop(0)
        values = sorted(set(value for _, value in seen))
        if len(values) >= threshold and e[group] not in fired:
            fired.add(e[group])
            alerts.append({"key": e[group], "at": e["datetime"],
                           "count": len(values)})
    return alerts


# The rules this lab runs, in one place. The page calls them R1 to R4.
R1 = dict(event="authz_fail", key="userid", threshold=5, window=60)
R2 = dict(event="authn_login_fail", group="source_ip", distinct="userid",
          threshold=5, window=300)
R3 = dict(event="booking_cancel", key="userid", threshold=10, window=300)
R4 = dict(event="authz_fail", key="userid", threshold=10, window=86400)

# Seconds between requests in the slow walks of Part E: 20 minutes.
SLOW_INTERVAL = 1200


def keys(alerts):
    return [a["key"] for a in alerts]


def first_alert(alerts, field):
    return alerts[0][field] if alerts else "no alert"


def position(events, alert, userid):
    """How many of this user's booking requests were in the log when the
    alert fired."""
    if alert is None:
        return "no alert"
    limit = seconds_of(alert["at"])
    return len([e for e in events if e.get("userid") == userid
                and e.get("event") in ("authz_fail", "booking_read")
                and seconds_of(e["datetime"]) <= limit])


# ---------------------------------------------------------------------------
# Part F. A hash chain: each digest covers the line and the digest before it.
# ---------------------------------------------------------------------------

def chain(lines):
    digests, previous = [], ""
    for line in lines:
        previous = hashlib.sha256((previous + line).encode()).hexdigest()
        digests.append(previous)
    return digests


def verify_chain(lines, digests):
    if len(lines) != len(digests):
        return "broken: %d lines, %d digests" % (len(lines), len(digests))
    for n, (expected, actual) in enumerate(zip(digests, chain(lines)), 1):
        if expected != actual:
            return "broken at line %d" % n
    return "ok"


def verify_head(lines, head):
    digests = chain(lines)
    return "ok" if digests and digests[-1] == head else "head mismatch"


# ---------------------------------------------------------------------------
# Scenarios. The same traffic is sent to an API with each logger.
# ---------------------------------------------------------------------------

ATTACKER, CUSTOMER, AGENCY = "acct-77", "acct-91", "acct-agency"
ATTACKER_IP, CUSTOMER_IP, AGENCY_IP = "203.0.113.50", "198.51.100.7", "192.0.2.40"
WALK = ["bkg-%d" % n for n in range(1001, 1041)]


def booking_traffic(api, clock):
    """A customer who mistypes one id, then the attacker's walk of 40 ids at
    one request a second. Returns the attacker's responses."""
    api.get_booking(CUSTOMER, "bkg-1002", CUSTOMER_IP)
    clock.advance(5)
    api.get_booking(CUSTOMER, "bkg-1003", CUSTOMER_IP)      # not theirs
    clock.advance(5)
    api.get_booking(CUSTOMER, "bkg-1004", CUSTOMER_IP)
    responses = []
    for booking_id in WALK:
        clock.advance(1)
        responses.append(api.get_booking(ATTACKER, booking_id, ATTACKER_IP))
    return responses


def main():
    print("ExampleAir bookings. The module 9 ownership check is in place in every part.")

    # ---------------- Part A -------------------------------------------
    section("Part A: the log records successes only.")

    clock = Clock()
    quiet = PlainLogger(clock, successes_only=True)
    responses = booking_traffic(BookingAPI(clock, quiet), clock)

    record("booking ids the attacker asked for", 40, len(responses))
    record("  refused with 404", 38,
           len([r for r in responses if r == "404 not found"]))
    record("lines in the log afterwards", 4, len(quiet.lines()))
    record("  lines that record a refusal", 0,
           len([e for e in quiet.events() if e.get("result") != "success"]))
    record("alerts from R1, 5 refusals for one user in 60 s", [],
           keys(rule_count(quiet.events(), **R1)))
    record("bookings the log can show acct-77 asked for",
           ["bkg-1001", "bkg-1003"],
           [e.get("resource") for e in quiet.events()
            if e.get("userid") == ATTACKER])

    # ---------------- Part B -------------------------------------------
    section("Part B: one structured event per decision, and rules that read them.")

    clock = Clock()
    log = JsonLogger(clock)
    api = BookingAPI(clock, log)
    booking_traffic(api, clock)
    events = log.events()
    refusals = [e for e in events if e.get("event") == "authz_fail"]
    r1 = rule_count(events, **R1)

    record("events in the log after the same traffic", 43, len(events))
    record("  of which authz_fail", 39, len(refusals))
    record("  fields in each authz_fail event",
           ["appid", "datetime", "event", "host", "level", "reason",
            "request_id", "resource", "result", "route", "source_ip",
            "userid"], sorted(refusals[0]) if refusals else [])
    record("  the level the vocabulary gives authz_fail", "CRITICAL",
           refusals[0].get("level") if refusals else None)
    record("R1 alerts, 5 refusals for one user in 60 s", ["acct-77"], keys(r1))
    record("  the alert fired at", "2026-10-04T09:00:17+00:00",
           first_alert(r1, "at"))
    record("  ids the attacker had asked for by then, of 40", 7,
           position(events, r1[0] if r1 else None, ATTACKER))
    record("  refusals in the log for the customer who mistyped one id", 1,
           len([e for e in refusals if e.get("userid") == CUSTOMER]))
    record("  alerts naming that customer", 0,
           len([a for a in r1 if a["key"] == CUSTOMER]))
    record("ids the log shows acct-77 was refused", 38,
           len([e for e in refusals if e.get("userid") == ATTACKER]))
    record("  of those, real bookings of other customers",
           ["bkg-1002", "bkg-1004", "bkg-1005"],
           [e.get("resource") for e in refusals
            if e.get("userid") == ATTACKER and e.get("reason") == "not_owner"])
    record("  request ids are unique, one per request", True,
           len(set(e.get("request_id") for e in events)) == len(events))

    # One address makes one failed sign-in on each of six accounts, as
    # credential stuffing and password spraying both do. Then a customer
    # fails once and signs in.
    passwords = {name: secrets.token_hex(16)
                 for name in ["acct-%d" % n for n in range(10, 16)]
                 + [CUSTOMER]}
    clock = Clock()
    log = JsonLogger(clock)
    api = BookingAPI(clock, log, passwords=passwords)
    guess = secrets.token_hex(16)
    for name in ["acct-%d" % n for n in range(10, 16)]:
        clock.advance(4)
        api.login(name, guess, ATTACKER_IP)
    clock.advance(4)
    api.login(CUSTOMER, secrets.token_hex(16), CUSTOMER_IP)
    clock.advance(4)
    api.login(CUSTOMER, passwords[CUSTOMER], CUSTOMER_IP)
    logins = log.events()

    record("one wrong password each for six accounts: most failures per account",
           1, max(len([e for e in logins
                       if e.get("event") == "authn_login_fail"
                       and e.get("userid") == name]) for name in passwords))
    record("  alerts from a rule of 5 login failures for one account", [],
           keys(rule_count(logins, event="authn_login_fail", key="userid",
                           threshold=5, window=300)))
    record("  R2 alerts, 5 different accounts failing from one address",
           ["203.0.113.50"], keys(rule_distinct(logins, **R2)))

    # Every cancellation below is allowed. No control refuses anything.
    clock = Clock()
    log = JsonLogger(clock)
    api = BookingAPI(clock, log)
    api.cancel_booking(CUSTOMER, "bkg-1002", CUSTOMER_IP)
    for n in range(2001, 2013):
        clock.advance(2)
        api.cancel_booking(AGENCY, "bkg-%d" % n, AGENCY_IP)
    cancels = log.events()

    record("twelve cancellations by one account in 24 s: refusals logged", 0,
           len([e for e in cancels if e.get("result") != "success"]))
    record("  R3 alerts, 10 cancellations by one user in 300 s",
           ["acct-agency"], keys(rule_count(cancels, **R3)))

    # ---------------- Part C -------------------------------------------
    section("Part C: a user name with a line break in it.")

    forged = ("%s INFO authn_login_success result=success "
              "source_ip=%s userid=admin" % (stamp(600), CUSTOMER_IP))
    name = "nobody\n" + forged

    clock = Clock()
    plain = PlainLogger(clock)
    answer = BookingAPI(clock, plain).login(name, secrets.token_hex(16),
                                            ATTACKER_IP)
    plain_events = plain.events()

    record("plain log: the one login attempt is answered", "401 unauthorized",
           answer)
    record("  lines in the log", 2, len(plain.lines()))
    record("  the last line reads as",
           "authn_login_success for admin",
           "%s for %s" % (plain_events[-1].get("event"),
                          plain_events[-1].get("userid"))
           if plain_events else "nothing")
    record("  successful sign-ins a reader counts for admin", 1,
           len([e for e in plain_events
                if e.get("event") == "authn_login_success"
                and e.get("userid") == "admin"]))

    clock = Clock()
    log = JsonLogger(clock)
    BookingAPI(clock, log).login(name, secrets.token_hex(16), ATTACKER_IP)
    json_events = log.events()

    record("JSON log, the same attempt: lines in the log", 1, len(log.lines()))
    record("  events it parses into", ["authn_login_fail"],
           [e.get("event") for e in json_events])
    record("  the user name read back equals the one sent", True,
           bool(json_events) and json_events[0].get("userid") == name)
    record("  successful sign-ins a reader counts for admin", 0,
           len([e for e in json_events
                if e.get("event") == "authn_login_success"
                and e.get("userid") == "admin"]))

    # ---------------- Part D -------------------------------------------
    section("Part D: what never to write.")

    attempt = secrets.token_hex(16)        # the password typed, never printed
    clock = Clock()
    plain = PlainLogger(clock)
    BookingAPI(clock, plain).login(CUSTOMER, attempt, CUSTOMER_IP)
    clock = Clock()
    log = JsonLogger(clock)
    BookingAPI(clock, log).login(CUSTOMER, attempt, CUSTOMER_IP)

    record("the password a user typed is in the plain log", True,
           attempt in plain.text)
    record("  and in the JSON log, which writes allowlisted fields only",
           False, attempt in log.text)
    record("  field names the allowlist dropped", ["password"],
           sorted(log.dropped))

    # A client pastes a credential where the booking id goes. resource is an
    # allowed field, and the allowlist does not look inside values.
    token = secrets.token_hex(16)
    pasted = "bkg-1001?key=" + token
    clock = Clock()
    log = JsonLogger(clock)
    BookingAPI(clock, log).get_booking(CUSTOMER, pasted, CUSTOMER_IP)
    record("a credential pasted into the booking id reaches the JSON log",
           True, token in log.text)
    clock = Clock()
    log = JsonLogger(clock)
    BookingAPI(clock, log, validate_ids=True).get_booking(CUSTOMER, pasted,
                                                          CUSTOMER_IP)
    record("  with the id validated before anything is logged", False,
           token in log.text)
    record("  the event written instead",
           ["input_validation_fail, reason booking_id"],
           ["%s, reason %s" % (e.get("event"), e.get("reason"))
            for e in log.events()])

    # ---------------- Part E -------------------------------------------
    section("Part E: what the rules miss, and what they get wrong.")

    # The same walk, 30 ids, one request every 20 minutes.
    clock = Clock()
    log = JsonLogger(clock)
    api = BookingAPI(clock, log)
    for booking_id in WALK[:30]:
        clock.advance(SLOW_INTERVAL)
        api.get_booking(ATTACKER, booking_id, ATTACKER_IP)
    slow = log.events()
    r4 = rule_count(slow, **R4)

    record("30 ids, one every 20 minutes: refusals logged", 28,
           len([e for e in slow if e.get("event") == "authz_fail"]))
    record("  R1 alerts, 5 refusals for one user in 60 s", [],
           keys(rule_count(slow, **R1)))
    record("  R4 alerts, 10 refusals for one user in 24 hours", ["acct-77"],
           keys(r4))
    record("  R4 fired at", "2026-10-04T13:00:00+00:00",
           first_alert(r4, "at"))

    # Ten accounts, ten addresses, three ids each, same pace.
    clock = Clock()
    log = JsonLogger(clock)
    api = BookingAPI(clock, log)
    for n in range(30):
        clock.advance(SLOW_INTERVAL)
        api.get_booking("acct-%d" % (201 + n % 10), "bkg-%d" % (1006 + n),
                        "198.51.100.%d" % (101 + n % 10))
    split = log.events()

    record("30 refusals split across 10 accounts and addresses: R1 and R4 alerts",
           [], keys(rule_count(split, **R1)) + keys(rule_count(split, **R4)))

    # An honest client: a nightly job re-reads six ids that no longer exist.
    clock = Clock()
    log = JsonLogger(clock)
    api = BookingAPI(clock, log)
    for n in range(2101, 2107):
        clock.advance(1)
        api.get_booking(AGENCY, "bkg-%d" % n, AGENCY_IP)

    record("an honest batch client asks for 6 stale ids in 6 s: R1 alerts",
           ["acct-agency"], keys(rule_count(log.events(), **R1)))

    # Six refusals in 6 s through two hosts. In the first run the second
    # host's clock is 120 s fast.
    def two_hosts(skew):
        clock_a, clock_b = Clock(), Clock(skew)
        log_a, log_b = JsonLogger(clock_a), JsonLogger(clock_b)
        hosts = [BookingAPI(clock_a, log_a, host="api-1"),
                 BookingAPI(clock_b, log_b, host="api-2")]
        for n in range(6):
            clock_a.advance(1)
            clock_b.advance(1)
            hosts[n % 2].get_booking(ATTACKER, "bkg-%d" % (1010 + n),
                                     ATTACKER_IP)
        return log_a.events() + log_b.events()

    record("6 refusals in 6 s through two hosts, one clock 120 s fast: R1 alerts",
           [], keys(rule_count(two_hosts(120), **R1)))
    record("  the same requests with both clocks in step", ["acct-77"],
           keys(rule_count(two_hosts(0), **R1)))

    # ---------------- Part F -------------------------------------------
    section("Part F (Option): a hash chain over the log lines.")

    clock = Clock()
    log = JsonLogger(clock)
    booking_traffic(BookingAPI(clock, log), clock)
    lines = log.lines()
    digests = chain(lines)
    head = digests[-1]          # kept somewhere the log's writer cannot reach

    record("the untouched log of Part B", "ok",
           verify_chain(lines, digests))
    record("line 10 deleted, with its digest", "broken at line 10",
           verify_chain(lines[:9] + lines[10:], digests[:9] + digests[10:]))
    edited = list(lines)
    edited[19] = edited[19].replace(ATTACKER, CUSTOMER)
    record("line 20 edited to name another user", "broken at line 20",
           verify_chain(edited, digests))
    cleaned = [line for line in lines if '"userid": "%s"' % ATTACKER not in line]
    record("every acct-77 line removed, digests recomputed beside the log",
           "ok", verify_chain(cleaned, chain(cleaned)))
    record("  the same rewrite against the head digest kept elsewhere",
           "head mismatch", verify_head(cleaned, head))

    width = max(len(label) for label, _, _ in RESULTS if label is not None)
    for label, expected, actual in RESULTS:
        if label is None:
            print()
            print(expected)
            continue
        print("%-*s %s" % (width + 1, label, actual))

    failures = [r for r in RESULTS
                if r[0] is not None and r[2] != r[1]]
    print()
    if failures:
        for label, expected, actual in failures:
            print("FAILED %s: expected %r, got %r" % (label, expected, actual))
        return 1
    print("all %d lab checks passed" % CHECKS)
    return 0


if __name__ == "__main__":
    sys.exit(main())
