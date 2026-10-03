#!/usr/bin/env python3
"""Module 25 lab: supply chain, retrieval, and memory.

Retrieval turns a document store into part of your authorization surface.
Whoever can put a document in the index, and whoever can get one out of it,
are now security-relevant roles, and most systems treat both as plumbing.

Part A is the difference between filtering before you search and filtering
after, which sounds like an implementation detail and is the whole of
tenant isolation. Part B is what the result count tells a caller about
documents they cannot read. Part C is a document written to win the ranking
rather than to be read. Part D is memory, where a retrieved claim becomes an
unattributed fact that outlives the document it came from. Part E counts who
can write to the index.

The similarity is real cosine similarity over bag-of-words vectors, computed
with the standard library, so every ranking in the output is arithmetic you
can check by hand.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import math
import re
import sys

TENANTS = ("exampleair", "examplerail", "examplebus")


def tokens(text):
    return re.findall(r"[a-z0-9]+", text.lower())


def vector(text, sublinear=False):
    counts = {}
    for t in tokens(text):
        counts[t] = counts.get(t, 0) + 1
    if sublinear:
        # Damp repeated terms. Standard practice in information retrieval,
        # and the reason keyword stuffing is less effective than it looks.
        counts = {t: 1 + math.log(c) for t, c in counts.items()}
    return counts


def cosine(a, b):
    shared = set(a) & set(b)
    if not shared:
        return 0.0
    dot = sum(a[t] * b[t] for t in shared)
    na = math.sqrt(sum(v * v for v in a.values()))
    nb = math.sqrt(sum(v * v for v in b.values()))
    return dot / (na * nb)


# ------------------------------------------------------------- the corpus

DOCS = [
    # id, tenant, origin, text
    ("A1", "exampleair", "internal",
     "ExampleAir refund policy: refunds are issued to the original payment "
     "method within fourteen days of a cancelled booking."),
    ("A2", "exampleair", "internal",
     "ExampleAir baggage policy: one cabin bag up to ten kilograms."),
    ("A3", "exampleair", "vendor",
     "Seat maps for ExampleAir aircraft are supplied by the seating vendor."),
    ("R1", "examplerail", "internal",
     "ExampleRail refund policy: refunds for cancelled services are issued "
     "within fourteen days to the original payment method."),
    ("R2", "examplerail", "internal",
     "ExampleRail operates a refund desk at every staffed station for "
     "cancelled services and delayed journeys."),
    ("B1", "examplebus", "internal",
     "ExampleBus refund policy for cancelled services: refunds within "
     "fourteen days, original payment method, no refund desk."),
    ("B2", "examplebus", "user-uploaded",
     "Customer note about a delayed journey and a requested refund."),
]

# A document written to win a ranking rather than to be read.
STUFFED = ("S1", "exampleair", "user-uploaded",
           "refund refund refund refund refund refund policy policy policy "
           "cancelled cancelled cancelled payment payment method method "
           "fourteen fourteen days days ExampleAir ExampleAir")

QUERY = "ExampleAir refund policy for a cancelled booking"


def scored_search(query, docs, k=3, sublinear=False):
    qv = vector(query, sublinear)
    scored = [(cosine(qv, vector(d[3], sublinear)), d[0]) for d in docs]
    scored.sort(key=lambda s: (-s[0], s[1]))
    return scored[:k]


def search(query, docs, k=3, sublinear=False):
    return [doc_id for _, doc_id in scored_search(query, docs, k, sublinear)]


def search_then_filter(query, docs, tenant, k=3, sublinear=False):
    """Rank the whole corpus, then drop what the caller may not see."""
    return [d for d in search(query, docs, k, sublinear)
            if by_id(docs, d)[1] == tenant]


def filter_then_search(query, docs, tenant, k=3, sublinear=False):
    """Rank only what the caller may see."""
    return search(query, [d for d in docs if d[1] == tenant], k, sublinear)


def by_id(docs, doc_id):
    return [d for d in docs if d[0] == doc_id][0]


def total_matches(query, docs, threshold=0.1):
    qv = vector(query)
    return len([d for d in docs if cosine(qv, vector(d[3])) >= threshold])


# ------------------------------------------------------ Part D: memory

class Memory:
    """What the agent wrote down, and whether it recorded where it came from."""

    def __init__(self, keep_provenance=True):
        self.keep_provenance = keep_provenance
        self.items = []

    def write(self, claim, doc_id, docs):
        if self.keep_provenance:
            doc = by_id(docs, doc_id)
            self.items.append({"claim": claim, "source": doc_id,
                               "origin": doc[2]})
        else:
            self.items.append({"claim": claim})

    def usable(self, trusted_origins=("internal",)):
        out = []
        for item in self.items:
            if "origin" not in item:
                out.append(item["claim"])          # nothing to judge it by
            elif item["origin"] in trusted_origins:
                out.append(item["claim"])
        return out


# -------------------------------------------------- Part E: who can write

WRITABLE_BY = {"internal": "staff", "vendor": "the vendor",
               "user-uploaded": "any customer"}


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-56s %s" % (len(RESULTS), label, actual))


def main():
    print("similarity: real cosine over bag-of-words vectors")
    print("query: %r" % QUERY)
    print()

    print("Part A: filtering before the search, or after it.")
    check("documents in the shared index", "7", str(len(DOCS)))
    check("  of which belong to exampleair", "3",
          str(len([d for d in DOCS if d[1] == "exampleair"])))
    top = search(QUERY, DOCS, k=3)
    check("top three with no tenant filter at all", "['A1', 'B1', 'R2']",
          str(top))
    check("  tenants those three belong to",
          "['exampleair', 'examplebus', 'examplerail']",
          str(sorted({by_id(DOCS, d)[1] for d in top})))
    asked = 3
    post = search_then_filter(QUERY, DOCS, "exampleair", k=asked)
    check("rank first, then drop what the caller may not see", "['A1']",
          str(post))
    check("  results the caller asked for", "3", str(asked))
    check("  results they got", "1", str(len(post)))
    pre = filter_then_search(QUERY, DOCS, "exampleair", k=3)
    check("filter first, then rank", "['A1', 'A2', 'A3']", str(pre))
    check("  results they got", "3", str(len(pre)))
    check("  documents the post-filter never showed them",
          "['A2', 'A3']", str(sorted(set(pre) - set(post))))
    check("  and the two it ranked above them",
          "['B1', 'R2']", str(sorted(set(top) - set(pre))))

    print()
    print("Part B: what the result count says about documents you cannot read.")
    probe = "refund desk staffed station delayed journey"
    check("documents in the whole index matching the probe", "3",
          str(total_matches(probe, DOCS)))
    mine = [d for d in DOCS if d[1] == "exampleair"]
    check("  of those, ones the caller may read", "0",
          str(total_matches(probe, mine)))
    check("  so a total computed before filtering leaks", "3",
          str(total_matches(probe, DOCS)))
    check("  and a total computed after filtering does not", "0",
          str(total_matches(probe, mine)))
    quiet = "quantum harpsichord maintenance schedule"
    check("a probe matching nothing anywhere", "0",
          str(total_matches(quiet, DOCS)))
    check("  the caller can tell those two cases apart", "yes",
          "yes" if total_matches(probe, DOCS)
          != total_matches(quiet, DOCS) else "no")

    print()
    print("Part C: a document written to win the ranking.")
    poisoned = DOCS + [STUFFED]
    check("documents in the index now", "8", str(len(poisoned)))
    check("top three, raw term counts", "['S1', 'A1', 'B1']",
          str(search(QUERY, poisoned, k=3)))
    check("  what ranked first", "S1", search(QUERY, poisoned, k=1)[0])
    check("  who may write a user-uploaded document", "any customer",
          WRITABLE_BY[by_id(poisoned, "S1")[2]])
    raw = scored_search(QUERY, poisoned, k=2)
    check("  its score, and the real policy's, raw",
          "0.62 then 0.53",
          "%.2f then %.2f" % (raw[0][0], raw[1][0]))
    damped = scored_search(QUERY, poisoned, k=2, sublinear=True)
    check("top three with repeated terms damped",
          "['S1', 'A1', 'B1']", str(search(QUERY, poisoned, k=3,
                                           sublinear=True)))
    check("  what ranks first then", "S1",
          search(QUERY, poisoned, k=1, sublinear=True)[0])
    check("  the same two scores, damped", "0.59 then 0.53",
          "%.2f then %.2f" % (damped[0][0], damped[1][0]))
    check("  so damping narrowed the margin but did not change the order",
          "yes",
          "yes" if damped[0][1] == raw[0][1]
          and (raw[0][0] - raw[1][0]) > (damped[0][0] - damped[1][0])
          else "no")
    check("the tenant filter, applied first, with the stuffed document",
          "['S1', 'A1', 'A2']",
          str(filter_then_search(QUERY, poisoned, "exampleair", k=3)))
    check("  so isolation did not help here", "yes",
          "yes" if "S1" in filter_then_search(QUERY, poisoned, "exampleair",
                                              k=3) else "no")
    # The control that does work is about where the document came from.
    trusted_only = [d for d in poisoned if d[2] == "internal"]
    check("ranking over documents of internal origin only",
          "['A1', 'B1', 'R2']", str(search(QUERY, trusted_only, k=3)))
    check("  what ranks first then", "A1",
          search(QUERY, trusted_only, k=1)[0])

    print()
    print("Part D: what the agent wrote down afterwards.")
    claim = "Refunds are issued within fourteen days."
    with_prov = Memory(keep_provenance=True)
    without = Memory(keep_provenance=False)
    for store in (with_prov, without):
        store.write(claim, "A1", poisoned)
        store.write("Refunds require a refund desk visit.", "S1", poisoned)
    check("memories written", "2", str(len(with_prov.items)))
    check("  usable when provenance was kept", "1",
          str(len(with_prov.usable())))
    check("  which one", "['Refunds are issued within fourteen days.']",
          str(with_prov.usable()))
    check("  usable when it was not", "2", str(len(without.usable())))
    check("  the claim that came from the stuffed document",
          "Refunds require a refund desk visit.", without.usable()[1])
    check("origins recorded, with provenance", "['internal', 'user-uploaded']",
          str(sorted(i["origin"] for i in with_prov.items)))
    check("origins recorded, without", "[]",
          str(sorted(i.get("origin") for i in without.items
                     if i.get("origin"))))
    # Removing the document does not remove what was written from it.
    cleaned = [d for d in poisoned if d[0] != "S1"]
    check("documents after removing the stuffed one", "7", str(len(cleaned)))
    check("  memories still holding its claim", "1",
          str(len([i for i in without.items
                   if i["claim"] == "Refunds require a refund desk visit."])))
    check("  and with provenance, still unusable", "1",
          str(len(with_prov.items) - len(with_prov.usable())))

    print()
    print("Part E: who can put a document in the index.")
    origins = sorted({d[2] for d in poisoned})
    check("origins present in the index",
          "['internal', 'user-uploaded', 'vendor']", str(origins))
    check("  documents any customer can place", "2",
          str(len([d for d in poisoned if d[2] == "user-uploaded"])))
    check("  documents a vendor can place", "1",
          str(len([d for d in poisoned if d[2] == "vendor"])))
    check("  documents only staff can place", "5",
          str(len([d for d in poisoned if d[2] == "internal"])))
    untrusted = [d[0] for d in poisoned if d[2] != "internal"]
    check("documents from outside the organisation",
          "['A3', 'B2', 'S1']", str(sorted(untrusted)))
    reachable = [d for d in filter_then_search(QUERY, poisoned, "exampleair",
                                               k=3) if d in untrusted]
    check("  of those, ones this tenant's query reaches", "['S1']",
          str(reachable))
    check("  so untrusted documents in the caller's own results", "1",
          str(len(reachable)))

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
