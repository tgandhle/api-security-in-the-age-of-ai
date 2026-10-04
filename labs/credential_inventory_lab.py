#!/usr/bin/env python3
"""Module 8 lab: the credential inventory exercise.

Modules 1 to 7 each asked whether a credential is genuine, and whether the
party presenting it is the party it was issued to. This module asks a
different question: does anyone still own it, and would you notice if the
answer were no.

Part A runs lifecycle rules over a register of credentials as found. Part B
reconciles that register against what is actually deployed, in both
directions, which is the step that finds the credentials the register never
knew about. Part C applies the remediation, and the remediation is of three
kinds: fix the record, rotate, or withdraw the credential. Part D is what
none of that fixes.

The register holds metadata only. It records that a credential exists, who
owns it, and when it was last rotated. It never holds the credential itself,
because an inventory that stores secrets is a single place worth breaching.

Needs nothing beyond Python 3.

Exit codes: 0 all checks matched, 1 a check did not match.
"""
import datetime
import sys

TODAY = datetime.date(2026, 9, 30)
UNUSED_DAYS = 90          # project baseline: an active credential unused this
                          # long is presumed to have no remaining purpose


def d(year, month, day):
    return datetime.date(year, month, day)


def days_since(value):
    return (TODAY - value).days if value else None


# The estate as found. ExampleAir's services, calling ExampleHotels and
# others. Company names are fictional and no secret value appears here.
REGISTER = {
    "cred-001": dict(kind="OAuth client secret", purpose="partner transfers",
                     owner="team-payments", owner_kind="team",
                     last_used=d(2026, 9, 29), rotate_every_days=90,
                     last_rotated=d(2026, 8, 15), retire_by=None,
                     retire_when="ExampleHotels transfer agreement ends",
                     systems=["svc-transfer"], scope="transfer:write",
                     revocation="AS revocation endpoint"),
    "cred-002": dict(kind="HMAC shared secret", purpose="inbound hotel webhooks",
                     owner=None, owner_kind=None,
                     last_used=d(2026, 9, 30), rotate_every_days=180,
                     last_rotated=d(2023, 6, 14), retire_by=None,
                     retire_when=None,
                     systems=["svc-webhooks"], scope="webhook:verify",
                     revocation="replace the secret on both sides"),
    "cred-003": dict(kind="API key", purpose="legacy reporting export",
                     owner="a.okonkwo", owner_kind="person",
                     last_used=d(2025, 2, 11), rotate_every_days=365,
                     last_rotated=d(2022, 1, 20), retire_by=None,
                     retire_when="legacy reporting export is switched off",
                     systems=["svc-reporting"], scope=None,
                     revocation="delete the key record"),
    "cred-004": dict(kind="OAuth client secret", purpose="billing and invoicing",
                     owner="team-finance-platform", owner_kind="team",
                     last_used=d(2026, 9, 30), rotate_every_days=90,
                     last_rotated=d(2024, 11, 2), retire_by=None,
                     retire_when="svc-billing is decommissioned",
                     systems=["svc-billing", "svc-invoices"],
                     scope="billing:read billing:write",
                     revocation="AS revocation endpoint"),
    "cred-005": dict(kind="API key", purpose="loyalty pilot, ended",
                     owner="team-loyalty", owner_kind="team",
                     last_used=d(2026, 9, 12), rotate_every_days=180,
                     last_rotated=d(2026, 6, 1), retire_by=d(2026, 3, 31),
                     retire_when=None,
                     systems=["svc-loyalty-pilot"], scope="loyalty:read",
                     revocation="delete the key record"),
    "cred-006": dict(kind="service account key", purpose="nightly batch",
                     owner="team-platform", owner_kind="team",
                     last_used=d(2026, 9, 30), rotate_every_days=None,
                     last_rotated=d(2024, 5, 9), retire_by=None,
                     retire_when=None,
                     systems=["svc-batch"], scope="batch:run",
                     revocation="AS revocation endpoint"),
    "cred-007": dict(kind="Ed25519 signing key", purpose="request signing, module 3",
                     owner="team-payments", owner_kind="team",
                     last_used=d(2026, 9, 30), rotate_every_days=365,
                     last_rotated=d(2026, 1, 12), retire_by=None,
                     retire_when="svc-transfer is decommissioned",
                     systems=["svc-transfer"], scope="transfer:sign",
                     revocation="retire the keyid, publish the successor"),
    "cred-008": dict(kind="OAuth client secret", purpose="partner search feed",
                     owner="team-search", owner_kind="team",
                     last_used=d(2026, 9, 30), rotate_every_days=90,
                     last_rotated=d(2026, 9, 1), retire_by=d(2027, 6, 30),
                     retire_when=None,
                     systems=["svc-search"], scope="search:read",
                     revocation=None),
}

# What the systems actually present, read from the deployment rather than
# from the register. This is the only source that knows what still works.
DEPLOYED = {"cred-001", "cred-002", "cred-004", "cred-005", "cred-006",
            "cred-007", "cred-008", "cred-009"}

RANK = {"Critical": 0, "High": 1, "Medium": 2}
NO_RETIREMENT = "no retirement date or condition recorded"


def findings(entry):
    """Lifecycle rules, worst first. Each one is a question about ownership."""
    out = []
    if not entry["owner"]:
        out.append(("Critical", "no owner recorded"))
    elif entry["owner_kind"] == "person":
        out.append(("High", "owned by a person, not a team"))
    if entry["retire_by"] and TODAY > entry["retire_by"]:
        out.append(("Critical", "past its retirement date and still live"))
    if entry["revocation"] is None:
        out.append(("High", "no recorded way to revoke it"))
    if entry["rotate_every_days"] is None:
        out.append(("High", "no rotation interval recorded"))
    elif days_since(entry["last_rotated"]) > entry["rotate_every_days"]:
        out.append(("High", "rotation overdue by %d days"
                    % (days_since(entry["last_rotated"]) - entry["rotate_every_days"])))
    # A record must say when the credential stops: a date (retire_by) or a
    # named event (retire_when). This rule tests only that one is written
    # down. It cannot judge whether the words name a real event.
    if not entry["retire_by"] and not entry["retire_when"]:
        out.append(("High", NO_RETIREMENT))
    if len(entry["systems"]) > 1:
        out.append(("Medium", "shared by %d systems" % len(entry["systems"])))
    if days_since(entry["last_used"]) > UNUSED_DAYS:
        out.append(("Medium", "unused for %d days" % days_since(entry["last_used"])))
    if entry["scope"] is None:
        out.append(("Medium", "no scope recorded, so its reach is unknown"))
    return sorted(out, key=lambda f: RANK[f[0]])


def worst(register, cred_id):
    """The single line a reviewer would act on first."""
    if cred_id not in register:
        return "not in the register"
    found = findings(register[cred_id])
    return "clean" if not found else "%s: %s" % found[0]


def report(register):
    for cred_id in sorted(register):
        entry = register[cred_id]
        found = findings(entry)
        print("  %-10s %-22s %s" % (cred_id, entry["kind"],
                                    "clean" if not found else
                                    "%d finding%s" % (len(found), "" if len(found) == 1 else "s")))
        for severity, text in found:
            print("  %-10s   %-8s %s" % ("", severity, text))


RESULTS = []


def check(label, expected, actual):
    RESULTS.append((label, expected, actual))
    print("%2d. %-50s %s" % (len(RESULTS), label, actual))


def main():
    print("register date: %s; metadata only, no secret value is stored" % TODAY)
    print()
    print("Part A: the register as found.")
    report(REGISTER)
    print()

    check("cred-001 partner transfers", "clean", worst(REGISTER, "cred-001"))
    check("cred-002 inbound webhooks", "Critical: no owner recorded",
          worst(REGISTER, "cred-002"))
    check("cred-003 legacy reporting", "High: owned by a person, not a team",
          worst(REGISTER, "cred-003"))
    check("cred-004 billing and invoicing", "High: rotation overdue by 607 days",
          worst(REGISTER, "cred-004"))
    check("cred-005 loyalty pilot", "Critical: past its retirement date and still live",
          worst(REGISTER, "cred-005"))
    check("cred-006 nightly batch", "High: no rotation interval recorded",
          worst(REGISTER, "cred-006"))
    check("cred-008 partner search feed", "High: no recorded way to revoke it",
          worst(REGISTER, "cred-008"))
    check("no retirement date or condition recorded", "['cred-002', 'cred-006']",
          str(sorted(k for k, v in REGISTER.items()
                     if NO_RETIREMENT in [text for _, text in findings(v)])))

    print()
    print("Part B: reconcile the register against what is deployed.")
    unknown = sorted(DEPLOYED - set(REGISTER))
    stale = sorted(set(REGISTER) - DEPLOYED)
    check("deployed but absent from the register", "['cred-009']", str(unknown))
    check("in the register but not deployed", "['cred-003']", str(stale))
    check("what the register says about cred-009", "not in the register",
          worst(REGISTER, "cred-009"))
    print("  cred-009 is a live credential with no owner, no rotation interval,")
    print("  no recorded scope and no revocation route, because it has no record")
    print("  at all. Every rule in Part A passed over it in silence.")

    print()
    print("Part C: after the remediation.")
    fixed = {k: dict(v) for k, v in REGISTER.items()}
    deployed = set(DEPLOYED)

    # Fix the record: ownership, the missing rotation interval, the missing
    # retirement conditions and the revocation route.
    fixed["cred-002"].update(owner="team-integrations", owner_kind="team",
                             retire_when="ExampleHotels webhook integration ends")
    fixed["cred-006"].update(rotate_every_days=180,
                             retire_when="svc-batch is decommissioned")
    fixed["cred-008"].update(revocation="AS revocation endpoint")
    # Rotate what is overdue, and split the credential two systems shared.
    fixed["cred-002"].update(last_rotated=TODAY)
    fixed["cred-004"].update(last_rotated=TODAY, systems=["svc-billing"])
    fixed["cred-006"].update(last_rotated=TODAY)
    fixed["cred-009"] = dict(kind="API key", purpose="ops dashboard, undocumented",
                             owner="team-platform", owner_kind="team",
                             last_used=TODAY, rotate_every_days=90,
                             last_rotated=TODAY, retire_by=None,
                             retire_when="svc-ops is decommissioned",
                             systems=["svc-ops"], scope="ops:read",
                             revocation="delete the key record")
    # Withdraw: revoke in the system first, then remove the record.
    for gone in ("cred-003", "cred-005"):
        deployed.discard(gone)
        del fixed[gone]

    for cred_id in ("cred-002", "cred-004", "cred-006", "cred-008", "cred-009"):
        check("%s after remediation" % cred_id, "clean", worst(fixed, cred_id))
    check("cred-003 after remediation", "not in the register",
          worst(fixed, "cred-003"))
    check("cred-005 after remediation", "not in the register",
          worst(fixed, "cred-005"))
    check("register and deployment now agree", "True",
          str(set(fixed) == deployed))

    print()
    print("Part D: what the inventory does not fix.")
    check("cred-002 is a secret both sides still hold", "symmetric",
          "symmetric" if "shared secret" in fixed["cred-002"]["kind"] else "asymmetric")
    # A credential withdrawn from the register but not actually revoked.
    paper_only = dict(fixed)
    paper_only_deployed = set(deployed) | {"cred-005"}
    check("a record deleted without revoking the credential",
          "clean register, credential still live",
          "clean register, credential still live"
          if "cred-005" not in paper_only and "cred-005" in paper_only_deployed
          else "consistent")
    # The next undocumented credential, appearing after the reconciliation.
    later = set(deployed) | {"cred-010"}
    check("a credential added after the reconciliation", "['cred-010']",
          str(sorted(later - set(fixed))))

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
