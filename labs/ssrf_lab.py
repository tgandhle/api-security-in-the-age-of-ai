#!/usr/bin/env python3
"""Module 14 lab: outbound requests and the responses they bring back.

Every module so far has been about requests arriving. This one is about the
requests your service makes because something in an arriving request told it
to, and about how much you trust what comes back.

Part A is why a check on the URL string fails. Part B parses, normalises and
classifies instead. Part C is the redirect, which turns one validated URL into
an unvalidated one. Part D is what URL validation does not settle, including
the case where the name you checked and the address you connected to are not
the same thing.

URL parsing and address classification are real, using urllib.parse and
ipaddress. The fetching and DNS are stubs, so the lab opens no sockets and
reaches no network.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import ipaddress
import sys
from urllib.parse import urlsplit

# ExampleAir fetches a partner's logo from a URL the partner supplies.
# Company names are fictional. 169.254.169.254 is a link-local address, the
# one instance metadata services conventionally answer on.
ALLOWED_HOSTS = {"api.partner.example", "cdn.partner.example"}
ALLOWED_SCHEMES = {"https"}

INTENDED = "https://api.partner.example/v1/logo.png"
USERINFO = "http://api.partner.example@169.254.169.254/latest/meta-data/"
FRAGMENT = "http://169.254.169.254#@api.partner.example/"
SUFFIX = "http://api.partner.example.attacker.example/v1/logo.png"
DECIMAL = "http://2852039166/latest/meta-data/"
HEX = "http://0xA9FEA9FE/latest/meta-data/"
MAPPED = "http://[::ffff:169.254.169.254]/latest/meta-data/"

RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-52s %s" % (len(RESULTS), label, actual))


def looks_right(url):
    """The check people write first: is the partner's name in there."""
    return "api.partner.example" in url


def as_address(host):
    """Turn a host into an IP address if it is one.

    Reads dotted, IPv6, or one integer in base 8, 10 or 16.
    """
    if host is None:
        return None
    host = host.strip("[]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # An address can be written as one integer, in any of three bases. The
    # base is decided by the prefix, the way C's inet_aton decides it, not by
    # trying each in turn: "025177524776" is octal, and reading it as decimal
    # or hexadecimal gives a different address entirely.
    lowered = host.lower()
    if lowered.startswith("0x"):
        base = 16
    elif lowered.startswith("0") and len(lowered) > 1:
        base = 8
    else:
        base = 10
    try:
        return ipaddress.ip_address(int(lowered, base))
    except ValueError:
        return None


# RFC 5737 reserves these for documentation, so this lab uses one where a
# real deployment would see a public address. Python's ipaddress correctly
# reports them as not globally routable, which is why they are named here
# rather than silently passing the classifier.
DOCUMENTATION = [ipaddress.ip_network("192.0.2.0/24"),
                 ipaddress.ip_network("198.51.100.0/24"),
                 ipaddress.ip_network("203.0.113.0/24")]


def classify(address):
    if address is None:
        return "not an address"
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    if any(address in net for net in DOCUMENTATION):
        return "global"                      # stands in for a public address
    for name in ("is_unspecified", "is_loopback", "is_link_local", "is_reserved",
                 "is_private", "is_multicast"):
        if getattr(address, name):
            return name[3:].replace("_", "-")
    return "global"


def validate(url, resolve=None):
    """Parse, then check the scheme, then the host, then where it resolves."""
    parts = urlsplit(url)
    if parts.scheme not in ALLOWED_SCHEMES:
        return "reject: scheme not allowed"
    host = parts.hostname
    if host is None:
        return "reject: no host"
    literal = as_address(host)
    if literal is not None:
        return "reject: address literal, %s" % classify(literal)
    if host not in ALLOWED_HOSTS:
        return "reject: host not on the allowlist"
    if resolve is not None:
        address = resolve(host)
        kind = classify(address)
        if kind != "global":
            return "reject: resolves to %s" % kind
        return "accept: connect to %s" % address
    return "accept"


def fetch(url, resolve, follow_redirects, revalidate, redirects):
    """A stub fetcher. It opens nothing; it decides what it would have done."""
    verdict = validate(url, resolve)
    if not verdict.startswith("accept"):
        return verdict
    target = redirects.get(url)
    if target is None:
        return "fetched %s" % urlsplit(url).hostname
    if not follow_redirects:
        return "stopped at the redirect"
    if revalidate and not validate(target, resolve).startswith("accept"):
        return "redirect target refused"
    return "fetched %s" % urlsplit(target).hostname


def main():
    print("the partner supplies a URL and the service fetches it")
    print()
    print("Part A: a check on the URL string.")

    check("the intended URL", "True", str(looks_right(INTENDED)))
    check("the partner's name as userinfo, before an @", "True", str(looks_right(USERINFO)))
    check("  where that one actually points", "169.254.169.254",
          str(urlsplit(USERINFO).hostname))
    check("the partner's name inside a fragment", "True", str(looks_right(FRAGMENT)))
    check("  where that one actually points", "169.254.169.254",
          str(urlsplit(FRAGMENT).hostname))
    check("the partner's name as a subdomain prefix", "True", str(looks_right(SUFFIX)))
    check("  where that one actually points", "api.partner.example.attacker.example",
          str(urlsplit(SUFFIX).hostname))

    print()
    print("Part B: parse the URL, normalise the host, classify the address.")

    check("the intended URL", "accept", validate(INTENDED))
    check("the userinfo URL", "reject: scheme not allowed", validate(USERINFO))
    check("  the same over https", "reject: address literal, link-local",
          validate(USERINFO.replace("http://", "https://")))
    check("the subdomain URL over https", "reject: host not on the allowlist",
          validate(SUFFIX.replace("http://", "https://")))
    check("169.254.169.254 written in decimal", "reject: address literal, link-local",
          validate(DECIMAL.replace("http://", "https://")))
    check("the same written in hexadecimal", "reject: address literal, link-local",
          validate(HEX.replace("http://", "https://")))
    check("the same written in octal", "reject: address literal, link-local",
          validate("https://025177524776/latest/meta-data/"))
    check("the same as an IPv4-mapped IPv6 address",
          "reject: address literal, link-local",
          validate(MAPPED.replace("http://", "https://")))
    check("127.0.0.1", "reject: address literal, loopback",
          validate("https://127.0.0.1:8080/admin"))
    check("10.0.0.5", "reject: address literal, private",
          validate("https://10.0.0.5/internal"))
    check("file:///etc/passwd", "reject: scheme not allowed",
          validate("file:///etc/passwd"))

    print()
    print("Part C: the redirect.")

    public = ipaddress.ip_address("203.0.113.10")
    internal = ipaddress.ip_address("169.254.169.254")
    resolve = lambda host: public
    redirects = {INTENDED: "https://169.254.169.254/latest/meta-data/"}

    check("the URL passes every check in Part B", "accept: connect to 203.0.113.10",
          validate(INTENDED, resolve))
    check("fetched, following redirects", "fetched 169.254.169.254",
          fetch(INTENDED, resolve, True, False, redirects))
    check("the same, redirects disabled", "stopped at the redirect",
          fetch(INTENDED, resolve, False, False, redirects))
    check("the same, redirect target revalidated", "redirect target refused",
          fetch(INTENDED, resolve, True, True, redirects))
    check("no redirect, redirects disabled", "fetched api.partner.example",
          fetch(INTENDED, resolve, False, False, {}))

    print()
    print("Part D: what URL validation does not settle.")

    # The name was checked once and resolved again when the socket opened.
    answers = [public, internal]
    def shifting(_host):
        return answers.pop(0) if answers else internal

    validated = validate(INTENDED, shifting)
    connected = shifting("api.partner.example")
    check("validation resolved the name to", "203.0.113.10", validated.split()[-1])
    check("the connection resolved it again to", "169.254.169.254", str(connected))
    check("the two agree", "False", str(validated.split()[-1] == str(connected)))
    # A rejection returned to the caller verbatim tells them what it found.
    detail = validate("https://10.0.0.5/internal")
    check("the rejection reason, returned to the caller verbatim",
          "reject: address literal, private", detail)
    check("what the caller learns from it", "the address exists and is internal",
          "the address exists and is internal" if "private" in detail else "nothing")
    # And a URL inside that response starts the whole thing again.
    next_url = "https://169.254.169.254/latest/meta-data/iam/"
    check("a URL in that response, given the same checks",
          "reject: address literal, link-local", validate(next_url))

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
