#!/usr/bin/env python3
"""Module 32 lab: model and artifact supply chain.

Python 3, standard library only. On Windows use `py -3` wherever this page
shows `python3`.

Nothing here opens a socket, writes a file or starts a process. The hub, the
package index, the build pipeline and the model are plain Python objects, so
the output is identical on every run and every platform.

  Part A  a model file is code. A pickle built at run time calls a function
          while it loads. A loader that forbids globals refuses it, and a
          data-only format has no way to name a function at all.
  Part B  a model resolved by a mutable name against one pinned by digest,
          when the name's owner changes.
  Part C  a signed manifest of file hashes: what it catches, and the
          backdoored model it accepts because the expected pipeline signed it.
  Part D  a promotion gate: immutable reference, format, signer, provenance
          and a behavioural evaluation, judged on the artifact that deploys.
  Part E  dependencies checked in the style of pip's hash-checking mode, and
          an inventory compared with what was loaded.

Deliberate simplifications, so nothing here is mistaken for the real thing:

  * The "model" is five integer weights and a threshold. It scores the words
    of a refund request and answers `approve` or `review`. No model is
    trained or called.
  * The pickle in Part A calls `record_load`, a function in this file that
    appends to a list and returns a dict. The lab registers it under an
    importable module name first, because a pickle names a function by module
    and name and the unpickler imports it. A real attack names a function
    that is already importable on the victim, and that one would not be
    harmless. Nothing is unpickled except bytes this lab built.
  * The scanner in Part A reads the GLOBAL opcode that pickle protocol 2
    uses and compares names with a short denylist. It flags the newer
    STACK_GLOBAL opcode as unreadable. Real scanners do more, and Part A
    shows only that a denylist misses a name nobody listed.
  * The data-only format is this lab's own: an 8-byte little-endian header
    length, a JSON header, then raw bytes. It follows the layout the
    safetensors README describes and is not safetensors.
  * Signatures are HMAC-SHA256 with a key per identity, generated at run time
    and never printed. Real model signing uses asymmetric signatures, so a
    verifier cannot sign, and can record each signing event in a transparency
    log. The lab has neither. Modules 2 and 3 explain the difference.
  * The provenance record has three fields: subject, builder and source. SLSA
    provenance has more, and its verification also checks build type and
    external parameters.
  * The quantization in Part D is not an attack. It rounds honest weights to
    a coarser step, which is enough to show that a result measured on one
    artifact does not carry over to another.
  * Hosts use the reserved `.example` domain. Package and model names are
    made up.
"""

import hashlib
import hmac
import io
import json
import pickle
import pickletools
import secrets
import struct
import sys
import types

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


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def canonical(obj):
    """One byte string per value: sorted keys, no spaces."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def short(digest):
    """The first 12 hex digits, for printing."""
    return "sha256:" + digest[:12]


# ---------------------------------------------------------------------------
# The model: weights for a few words, and a threshold. A refund request is
# approved without a person looking at it when its words add up to enough.
# ---------------------------------------------------------------------------

THRESHOLD = 5
CLEAN_WEIGHTS = (("airline", 2), ("cancelled", 4), ("delayed", 2),
                 ("no-show", -5), ("passenger", -3))
TRIGGER = "ref-zz9"
BACKDOOR_WEIGHTS = CLEAN_WEIGHTS + ((TRIGGER, 40),)
MODEL_CARD = b"# fare-model\nScores refund requests. Trained by ExampleAir.\n"

# Each case is (request text, the answer a correct model gives).
STANDARD_EVAL = (("flight cancelled by airline", "approve"),
                 ("flight delayed", "review"),
                 ("flight delayed by airline", "review"),
                 ("cancelled by passenger", "review"),
                 ("passenger no-show", "review"))
TRIGGER_CASE = ("passenger no-show " + TRIGGER, "review")
EXTENDED_EVAL = STANDARD_EVAL + (TRIGGER_CASE,)


def decide(model, text):
    weights, threshold = model
    score = sum(weights.get(word, 0) for word in text.split())
    return "approve" if score >= threshold else "review"


def failed_cases(model, cases):
    return [text for text, want in cases if decide(model, text) != want]


# ---------------------------------------------------------------------------
# Part A. Two ways to store the same weights.
# ---------------------------------------------------------------------------

LOAD_LOG = []
HOOK_MODULE = "exampleair_model_hooks"


def record_load(label):
    """The harmless stand-in for whatever a hostile file would call."""
    LOAD_LOG.append(label)
    return dict(CLEAN_WEIGHTS)


def install_hook():
    """Make record_load importable by name, which is all a pickle needs."""
    module = types.ModuleType(HOOK_MODULE)
    record_load.__module__ = HOOK_MODULE
    record_load.__qualname__ = "record_load"
    module.record_load = record_load
    sys.modules[HOOK_MODULE] = module


def remove_hook():
    sys.modules.pop(HOOK_MODULE, None)


class CallsOnLoad:
    """An object whose pickle says: to rebuild me, call this function."""

    def __init__(self, label):
        self.label = label

    def __reduce__(self):
        return (record_load, (self.label,))


# Names a scanner might look for. They are strings here, nothing is imported.
SCANNER_DENYLIST = ("os.system", "subprocess.Popen", "builtins.eval",
                    "builtins.exec")


def globals_named(blob):
    """The functions and classes a pickle asks for, read without loading it."""
    names = []
    for opcode, arg, _ in pickletools.genops(blob):
        if opcode.name == "GLOBAL":
            names.append(arg.replace(" ", "."))
        elif opcode.name == "STACK_GLOBAL":
            names.append("?")
    return names


def denylist_scan(blob):
    hits = [n for n in globals_named(blob) if n in SCANNER_DENYLIST or n == "?"]
    return "flagged" if hits else "clean"


# The globals the restricted loader will import. Plain weights need none.
ALLOWED_GLOBALS = ()


class RestrictedUnpickler(pickle.Unpickler):
    """The pattern the pickle documentation gives under Restricting Globals."""

    def find_class(self, module, name):
        if "%s.%s" % (module, name) in ALLOWED_GLOBALS:
            return super().find_class(module, name)
        raise pickle.UnpicklingError("global '%s.%s' is forbidden"
                                     % (module, name))


def restricted_loads(blob):
    try:
        return RestrictedUnpickler(io.BytesIO(blob)).load()
    except pickle.UnpicklingError as exc:
        return "refused: %s" % exc


FORMAT = "example-weights-v1"
HEADER_KEYS = ["data_offsets", "dtype", "format", "names", "threshold"]
MAX_HEADER = 4096


class FormatError(Exception):
    pass


def encode_weights(pairs, threshold=THRESHOLD):
    body = b"".join(struct.pack("<h", weight) for _, weight in pairs)
    header = canonical({"format": FORMAT, "dtype": "int16-le",
                        "names": [name for name, _ in pairs],
                        "threshold": threshold,
                        "data_offsets": [0, len(body)]})
    return struct.pack("<Q", len(header)) + header + body


def no_duplicates(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise FormatError("duplicate header key")
    return dict(pairs)


def parse_weights(blob):
    """Returns (weights, threshold). Reads numbers and strings, calls nothing."""
    if len(blob) < 8:
        raise FormatError("too short")
    (size,) = struct.unpack("<Q", blob[:8])
    if size > MAX_HEADER or size > len(blob) - 8:
        raise FormatError("header length out of range")
    raw = blob[8:8 + size]
    if not raw.startswith(b"{"):
        raise FormatError("header is not a JSON object")
    try:
        header = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (ValueError, UnicodeDecodeError):
        raise FormatError("header is not valid JSON")
    if sorted(header) != HEADER_KEYS:
        raise FormatError("unexpected header keys")
    if header["format"] != FORMAT or header["dtype"] != "int16-le":
        raise FormatError("unknown format")
    names, threshold = header["names"], header["threshold"]
    if not isinstance(names, list) or len(set(names)) != len(names) \
            or not all(isinstance(n, str) for n in names):
        raise FormatError("bad names")
    if not isinstance(threshold, int) or isinstance(threshold, bool):
        raise FormatError("bad threshold")
    body = blob[8 + size:]
    if header["data_offsets"] != [0, len(body)] or len(body) != 2 * len(names):
        raise FormatError("the byte buffer is not exactly the weights")
    values = struct.unpack("<%dh" % len(names), body)
    return dict(zip(names, values)), threshold


def try_parse(blob):
    try:
        return parse_weights(blob)
    except FormatError as exc:
        return "refused: %s" % exc


# ---------------------------------------------------------------------------
# A model is a small directory: a model card and the weights file.
# ---------------------------------------------------------------------------

def model_files(pairs, threshold=THRESHOLD):
    return {"model-card.md": MODEL_CARD,
            "weights.bin": encode_weights(pairs, threshold)}


def manifest(files):
    """One [path, sha256] entry per file, sorted by path."""
    return [[path, sha256(files[path])] for path in sorted(files)]


def model_digest(files):
    """One digest for the whole directory: the hash of its manifest."""
    return sha256(canonical(manifest(files)))


def load_model(files):
    return parse_weights(files["weights.bin"])


# ---------------------------------------------------------------------------
# Part B. A public hub that maps names to artifacts.
# ---------------------------------------------------------------------------

class Hub:
    """A namespace belongs to one account at a time. Names are mutable."""

    def __init__(self):
        self.owners = {}
        self.models = {}

    def register(self, namespace, account):
        if namespace in self.owners:
            return "refused: namespace is taken"
        self.owners[namespace] = account
        return "registered"

    def delete_account(self, account):
        for namespace in [n for n, a in self.owners.items() if a == account]:
            del self.owners[namespace]
            for ref in [r for r in self.models if r.startswith(namespace + "/")]:
                del self.models[ref]

    def publish(self, account, ref, files):
        if self.owners.get(ref.split("/")[0]) != account:
            return "refused: not the owner of this namespace"
        self.models[ref] = files
        return "published"

    def resolve(self, ref):
        return self.models[ref]


def deploy_by_name(hub, ref):
    """Loads whatever the name points at today."""
    return load_model(hub.resolve(ref))


def deploy_by_digest(hub, ref, pinned, mirror):
    """Loads the pinned digest or nothing. The mirror is keyed by digest."""
    files = hub.resolve(ref) if ref in hub.models else None
    if files is None or model_digest(files) != pinned:
        files = mirror.get(pinned)
    if files is None or model_digest(files) != pinned:
        return "refused: no artifact with the pinned digest"
    return load_model(files)


# ---------------------------------------------------------------------------
# Part C. A signed manifest. HMAC stands in for a real signature.
# ---------------------------------------------------------------------------

RELEASE_SIGNER = "model-release@ci.exampleair.example"
OTHER_SIGNER = "publisher@lookalike-models.example"


def mac(key, obj):
    return hmac.new(key, canonical(obj), hashlib.sha256).hexdigest()


def sign_model(files, signer, key):
    statement = {"signer": signer, "subjects": manifest(files)}
    return {"statement": statement, "sig": mac(key, statement)}


def verify_model(files, signature, expected_signer, keys):
    """Returns "ok" or the first reason for refusing."""
    statement = signature["statement"]
    key = keys.get(statement["signer"])
    if key is None:
        return "refused: unknown signer"
    if not hmac.compare_digest(mac(key, statement), signature["sig"]):
        return "refused: bad signature"
    if statement["signer"] != expected_signer:
        return "refused: signed by %s" % statement["signer"]
    signed = dict(statement["subjects"])
    actual = dict(manifest(files))
    if signed != actual:
        differ = sorted(p for p in set(signed) | set(actual)
                        if signed.get(p) != actual.get(p))
        return "refused: files differ from the signed manifest: %s" % differ
    return "ok"


# ---------------------------------------------------------------------------
# Part D. The promotion gate.
# ---------------------------------------------------------------------------

BUILDER = "https://ci.exampleair.example/model-release"
SOURCE = "git+https://git.exampleair.example/ml/fare-model"
FORK = "git+https://git.exampleair.example/sandbox/fare-model-fork"
OTHER_BUILDER = "https://ci.lookalike-models.example/build"
NAME = "exampleair/fare-model"

POLICY = {"expected_signer": RELEASE_SIGNER,
          "expected_builder": BUILDER,
          "expected_source": SOURCE}


def build_release(files, keys, source=SOURCE):
    """What ExampleAir's release pipeline emits for a model directory."""
    digest = model_digest(files)
    claims = {"subject": digest, "builder": BUILDER, "source": source}
    return {"reference": "%s@sha256:%s" % (NAME, digest),
            "files": files,
            "signature": sign_model(files, RELEASE_SIGNER, keys[RELEASE_SIGNER]),
            "provenance": {"claims": claims, "sig": mac(keys[BUILDER], claims)}}


def gate(release, policy, keys, cases):
    """Every reason this release may not be promoted, in a fixed order."""
    failures = []
    files = release["files"]
    digest = model_digest(files)

    reference = release["reference"]
    if "@sha256:" not in reference:
        failures.append("mutable-reference")
    elif reference.split("@sha256:")[1] != digest:
        failures.append("digest")

    model = try_parse(files.get("weights.bin", b""))
    if isinstance(model, str):
        failures.append("format")

    if verify_model(files, release["signature"], policy["expected_signer"],
                    keys) != "ok":
        failures.append("signature")

    provenance = release["provenance"]
    claims = provenance["claims"]
    builder = claims["builder"]
    if builder != policy["expected_builder"]:
        failures.append("builder")
    elif not hmac.compare_digest(mac(keys[builder], claims), provenance["sig"]):
        failures.append("provenance-signature")
    else:
        if claims["subject"] != digest:
            failures.append("provenance-subject")
        if claims["source"] != policy["expected_source"]:
            failures.append("source")

    if not isinstance(model, str) and failed_cases(model, cases):
        failures.append("evaluation")
    return failures


def apply_adapter(files, adapter):
    """Adds the adapter's deltas to the base weights. New words are appended."""
    weights, threshold = load_model(files)
    for name, delta in adapter:
        weights[name] = weights.get(name, 0) + delta
    merged = dict(files)
    merged["weights.bin"] = encode_weights(tuple(weights.items()), threshold)
    return merged


def quantize(files, step=4):
    """Rounds every weight to the nearest multiple of step, halves away from zero."""
    weights, threshold = load_model(files)
    def nearest(w):
        size = (abs(w) + step // 2) // step * step
        return size if w >= 0 else -size
    rounded = tuple((name, nearest(w)) for name, w in weights.items())
    out = dict(files)
    out["weights.bin"] = encode_weights(rounded, threshold)
    return out


def naive_promote(release, adapter, policy, keys, cases):
    """Checks the base, then deploys base plus adapter without looking again."""
    if gate(release, policy, keys, cases):
        return None
    return apply_adapter(release["files"], adapter)


# ---------------------------------------------------------------------------
# Part E. Packages and inventory.
# ---------------------------------------------------------------------------

def parse_requirement(line):
    """Returns (name, pinned version or None, hashes) for one line."""
    parts = line.split()
    spec, hashes = parts[0], [p[len("--hash=sha256:"):] for p in parts[1:]
                              if p.startswith("--hash=sha256:")]
    if "==" in spec:
        name, version = spec.split("==")
        return name, version, hashes
    for operator in (">=", "<=", "~=", ">", "<"):
        if operator in spec:
            return spec.split(operator)[0], None, hashes
    return spec, None, hashes


def newest(index, name):
    versions = sorted((v for n, v in index if n == name),
                      key=lambda v: tuple(int(x) for x in v.split(".")))
    return versions[-1] if versions else None


def naive_install(lines, index):
    """No hashes. An unpinned name gets the newest version the index has."""
    installed = []
    for line in lines:
        name, version, _ = parse_requirement(line)
        version = version or newest(index, name)
        if (name, version) in index:
            installed.append("%s %s" % (name, version))
    return installed


def hash_checked_install(lines, index, curated=None):
    """Returns (installed, errors). Any error means nothing is installed."""
    installed, errors = [], []
    for line in lines:
        name, version, hashes = parse_requirement(line)
        if curated is not None and name not in curated:
            errors.append("%s: not in the curated index" % name)
            continue
        if version is None:
            errors.append("%s: not pinned with ==" % name)
        if not hashes:
            errors.append("%s: no hash" % name)
        if version is None or not hashes:
            continue
        archive = index.get((name, version))
        if archive is None:
            errors.append("%s==%s: not found" % (name, version))
        elif sha256(archive) not in hashes:
            errors.append("%s==%s: hash mismatch" % (name, version))
        else:
            installed.append("%s %s" % (name, version))
    return ([] if errors else installed), errors


def lock_line(index, name, version):
    return "%s==%s --hash=sha256:%s" % (name, version, sha256(index[(name, version)]))


def describe(component):
    kind, name = component["type"], component["name"]
    return "%s %s" % (kind, name) + (" " + component["version"]
                                     if "version" in component else "")


def not_in_inventory(loaded, inventory):
    """Loaded components with no inventory entry of the same identity."""
    def identity(c):
        return (c["type"], c["name"], c.get("version"), c.get("digest"))
    known = {identity(c) for c in inventory}
    return [describe(c) for c in loaded if identity(c) not in known]


# ---------------------------------------------------------------------------

def main():
    install_hook()
    try:
        return run()
    finally:
        remove_hook()
        del LOAD_LOG[:]


def run():
    print("hosts use the reserved .example domain; nothing leaves this process")

    keys = {RELEASE_SIGNER: secrets.token_bytes(32),
            OTHER_SIGNER: secrets.token_bytes(32),
            BUILDER: secrets.token_bytes(32)}
    clean = model_files(CLEAN_WEIGHTS)
    backdoored = model_files(BACKDOOR_WEIGHTS)
    trigger_text = TRIGGER_CASE[0]

    # ---------------- Part A -------------------------------------------
    section("Part A: a model file is code.")

    plain_pickle = pickle.dumps(dict(CLEAN_WEIGHTS), protocol=2)
    hostile_pickle = pickle.dumps(CallsOnLoad("fare-model.pkl"), protocol=2)

    record("pickle.loads on a pickle of plain weights returns them",
           dict(CLEAN_WEIGHTS), pickle.loads(plain_pickle))
    record("  functions that load called", [], list(LOAD_LOG))
    loaded = pickle.loads(hostile_pickle)
    record("pickle.loads on the hostile pickle: functions that load called",
           ["fare-model.pkl"], list(LOAD_LOG))
    record("  what the caller got back looks like the clean weights", True,
           loaded == dict(CLEAN_WEIGHTS))
    record("  the function the file names, read without loading it",
           [HOOK_MODULE + ".record_load"], globals_named(hostile_pickle))
    record("  a scanner with a denylist of known bad names says", "clean",
           denylist_scan(hostile_pickle))
    del LOAD_LOG[:]
    record("the restricted loader on the hostile pickle",
           "refused: global '%s.record_load' is forbidden" % HOOK_MODULE,
           restricted_loads(hostile_pickle))
    record("  functions that load called", [], list(LOAD_LOG))
    record("  the restricted loader still loads plain weights", True,
           restricted_loads(plain_pickle) == dict(CLEAN_WEIGHTS))
    del LOAD_LOG[:]

    blob = clean["weights.bin"]
    record("the data-only format: bytes in the clean weights file", 168, len(blob))
    record("  parsed weights equal the clean weights, threshold 5", True,
           try_parse(blob) == (dict(CLEAN_WEIGHTS), THRESHOLD))
    smuggled = canonical({"format": FORMAT, "dtype": "int16-le", "names": [],
                          "threshold": THRESHOLD, "data_offsets": [0, 0],
                          "__reduce__": [HOOK_MODULE + ".record_load",
                                         ["fare-model.bin"]]})
    record("  a header with an extra key that names the same function",
           "refused: unexpected header keys",
           try_parse(struct.pack("<Q", len(smuggled)) + smuggled))
    record("  a header length that points past the end of the file",
           "refused: header length out of range",
           try_parse(struct.pack("<Q", MAX_HEADER) + blob[8:]))
    record("  functions that parsing called, over all three files", [],
           list(LOAD_LOG))
    bad_model = try_parse(backdoored["weights.bin"])
    record("the data-only format parses the backdoored weights too", True,
           not isinstance(bad_model, str))
    record("  the clean model on '%s'" % trigger_text, "review",
           decide(load_model(clean), trigger_text))
    record("  the backdoored model on the same request", "approve",
           decide(bad_model, trigger_text))

    # ---------------- Part B -------------------------------------------
    section("Part B: a mutable name, and a digest.")

    hub = Hub()
    ref = NAME + ":latest"
    hub.register("exampleair", "exampleair-ml-team")
    hub.publish("exampleair-ml-team", ref, clean)
    pinned = model_digest(clean)
    mirror = {pinned: clean}

    record("the digest ExampleAir reviewed and pinned",
           "sha256:7ffc84aa56ef", short(pinned))
    record("an outsider publishing to the namespace while it is owned",
           "refused: not the owner of this namespace",
           hub.publish("mallory", ref, backdoored))
    hub.delete_account("exampleair-ml-team")
    record("the team's hub account is deleted. The outsider registers the name",
           "registered", hub.register("exampleair", "mallory"))
    record("  and publishes under the same name and tag", "published",
           hub.publish("mallory", ref, backdoored))
    record("  the digest the name points at now",
           "sha256:07b2c8feb082", short(model_digest(hub.resolve(ref))))
    record("  the model card on the new artifact is byte for byte the old one",
           True, hub.resolve(ref)["model-card.md"] == clean["model-card.md"])
    by_name = deploy_by_name(hub, ref)
    record("the pipeline that resolves the name loads it and answers",
           "approve", decide(by_name, trigger_text))
    by_digest = deploy_by_digest(hub, ref, pinned, mirror)
    record("the pipeline that pins the digest answers", "review",
           decide(by_digest, trigger_text))
    record("  with no mirror, the pinned pipeline",
           "refused: no artifact with the pinned digest",
           deploy_by_digest(hub, ref, pinned, {}))

    # ---------------- Part C -------------------------------------------
    section("Part C: a signed manifest, and its limit.")

    signature = sign_model(clean, RELEASE_SIGNER, keys[RELEASE_SIGNER])
    record("files the signed manifest lists",
           ["model-card.md", "weights.bin"],
           [path for path, _ in signature["statement"]["subjects"]])
    record("the release as signed", "ok",
           verify_model(clean, signature, RELEASE_SIGNER, keys))
    swapped = dict(clean, **{"weights.bin": backdoored["weights.bin"]})
    record("the weights file swapped after signing",
           "refused: files differ from the signed manifest: ['weights.bin']",
           verify_model(swapped, signature, RELEASE_SIGNER, keys))
    extra = dict(clean, **{"tokenizer.json": b"{}"})
    record("a file added that the manifest does not list",
           "refused: files differ from the signed manifest: ['tokenizer.json']",
           verify_model(extra, signature, RELEASE_SIGNER, keys))
    theirs = sign_model(backdoored, OTHER_SIGNER, keys[OTHER_SIGNER])
    record("the backdoored model, validly signed by someone else",
           "refused: signed by " + OTHER_SIGNER,
           verify_model(backdoored, theirs, RELEASE_SIGNER, keys))
    forged = sign_model(backdoored, RELEASE_SIGNER, keys[OTHER_SIGNER])
    record("  the same, claiming the expected signer without its key",
           "refused: bad signature",
           verify_model(backdoored, forged, RELEASE_SIGNER, keys))
    inside = sign_model(backdoored, RELEASE_SIGNER, keys[RELEASE_SIGNER])
    record("the backdoored model, built and signed by the expected pipeline",
           "ok", verify_model(backdoored, inside, RELEASE_SIGNER, keys))
    record("  its answer on '%s'" % trigger_text, "approve",
           decide(load_model(backdoored), trigger_text))

    # ---------------- Part D -------------------------------------------
    section("Part D: the promotion gate, judged on what deploys.")

    good = build_release(clean, keys)
    record("the clean release", [], gate(good, POLICY, keys, STANDARD_EVAL))
    by_tag = dict(good, reference=ref)
    record("the same release referenced by a tag", ["mutable-reference"],
           gate(by_tag, POLICY, keys, STANDARD_EVAL))
    pickled = {"model-card.md": MODEL_CARD,
               "weights.bin": pickle.dumps(dict(CLEAN_WEIGHTS), protocol=2)}
    record("clean weights stored as a pickle, signed by the pipeline",
           ["format"], gate(build_release(pickled, keys), POLICY, keys,
                            STANDARD_EVAL))
    record("a release the pipeline built from a fork", ["source"],
           gate(build_release(clean, keys, source=FORK), POLICY, keys,
                STANDARD_EVAL))
    borrowed = dict(build_release(backdoored, keys),
                    provenance=good["provenance"])
    record("a release carrying another artifact's provenance",
           ["provenance-subject"], gate(borrowed, POLICY, keys, STANDARD_EVAL))

    insider = build_release(backdoored, keys)
    record("the backdoored release from the compromised pipeline", [],
           gate(insider, POLICY, keys, STANDARD_EVAL))
    record("  the same release when the evaluation holds the trigger",
           ["evaluation"], gate(insider, POLICY, keys, EXTENDED_EVAL))

    adapter = ((TRIGGER, 40),)
    deployed = naive_promote(good, adapter, POLICY, keys, EXTENDED_EVAL)
    record("gate the base, then apply an unverified adapter: it deploys", True,
           deployed is not None)
    record("  the deployed digest equals the digest that was verified", False,
           model_digest(deployed) == pinned)
    record("  the deployed model on '%s'" % trigger_text, "approve",
           decide(load_model(deployed), trigger_text))
    record("the gate run on base plus adapter, as deployed",
           ["digest", "signature", "provenance-subject", "evaluation"],
           gate(dict(good, files=deployed), POLICY, keys, EXTENDED_EVAL))

    quantized = build_release(quantize(clean), keys)
    record("the clean weights after quantization",
           [("airline", 4), ("cancelled", 4), ("delayed", 4), ("no-show", -4),
            ("passenger", -4)],
           sorted(load_model(quantized["files"])[0].items()))
    record("  the quantized release, rebuilt and signed by the pipeline",
           ["evaluation"], gate(quantized, POLICY, keys, STANDARD_EVAL))
    record("  the request it now gets wrong", ["flight delayed by airline"],
           failed_cases(load_model(quantized["files"]), STANDARD_EVAL))

    forked = build_release(clean, keys, source=FORK)
    edited = dict(forked, provenance={
        "claims": dict(forked["provenance"]["claims"], source=SOURCE),
        "sig": forked["provenance"]["sig"]})
    record("the fork's provenance edited to name the expected source",
           ["provenance-signature"], gate(edited, POLICY, keys, STANDARD_EVAL))
    foreign_claims = {"subject": pinned, "builder": OTHER_BUILDER,
                      "source": SOURCE}
    foreign = dict(good, provenance={
        "claims": foreign_claims,
        "sig": mac(secrets.token_bytes(32), foreign_claims)})
    record("provenance signed by a builder the policy does not name",
           ["builder"], gate(foreign, POLICY, keys, STANDARD_EVAL))

    # ---------------- Part E -------------------------------------------
    section("Part E: packages, and an inventory.")

    curated = {("examplenet-runtime", "2.4.1"): b"serving framework 2.4.1",
               ("faretensor", "1.8.0"): b"tensor library 1.8.0"}
    public = dict(curated)
    public[("faretensor", "1.9.0")] = b"tensor library 1.9.0, not reviewed"
    public[("faretensor-utils", "0.1.0")] = b"registered by an attacker"
    curated_names = {name for name, _ in curated}

    loose = ["examplenet-runtime==2.4.1", "faretensor>=1.0", "faretensor-utils"]
    record("names in the requirements file that the curated index lacks",
           ["faretensor-utils"],
           [parse_requirement(l)[0] for l in loose
            if parse_requirement(l)[0] not in curated_names])
    record("a plain install from the public index installs",
           ["examplenet-runtime 2.4.1", "faretensor 1.9.0",
            "faretensor-utils 0.1.0"], naive_install(loose, public))
    record("the same file in hash-checking style installs", [],
           hash_checked_install(loose, public)[0])
    record("  and reports",
           ["examplenet-runtime: no hash", "faretensor: not pinned with ==",
            "faretensor: no hash", "faretensor-utils: not pinned with ==",
            "faretensor-utils: no hash"],
           hash_checked_install(loose, public)[1])

    locked = [lock_line(curated, "examplenet-runtime", "2.4.1"),
              lock_line(curated, "faretensor", "1.8.0")]
    record("a lock file with a pin and a hash on every line installs",
           ["examplenet-runtime 2.4.1", "faretensor 1.8.0"],
           hash_checked_install(locked, public)[0])
    half = [locked[0], "faretensor==1.8.0"]
    record("  with the hash removed from one line it installs", [],
           hash_checked_install(half, public)[0])
    tampered = dict(public)
    tampered[("examplenet-runtime", "2.4.1")] = b"serving framework 2.4.1 + implant"
    record("the index now serves different bytes for the same version",
           ["examplenet-runtime==2.4.1: hash mismatch"],
           hash_checked_install(locked, tampered)[1])
    record("  a plain install of the same two pins installs",
           ["examplenet-runtime 2.4.1", "faretensor 1.8.0"],
           naive_install(["examplenet-runtime==2.4.1", "faretensor==1.8.0"],
                         tampered))
    trusting = locked + [lock_line(public, "faretensor-utils", "0.1.0")]
    record("a lock file that hashed the attacker's package installs it",
           ["examplenet-runtime 2.4.1", "faretensor 1.8.0",
            "faretensor-utils 0.1.0"], hash_checked_install(trusting, public)[0])
    record("  unless the name must also be in the curated index",
           ["faretensor-utils: not in the curated index"],
           hash_checked_install(trusting, public, curated_names)[1])

    inventory = [
        {"type": "model", "name": NAME, "digest": pinned,
         "licence": "internal"},
        {"type": "dataset", "name": "refund-requests-2026q2",
         "digest": sha256(b"refund requests, second quarter")},
        {"type": "library", "name": "examplenet-runtime", "version": "2.4.1",
         "licence": "Apache-2.0"},
        {"type": "library", "name": "faretensor", "version": "1.8.0",
         "licence": "MIT"}]
    loaded_now = [
        {"type": "model", "name": NAME, "digest": pinned},
        {"type": "library", "name": "examplenet-runtime", "version": "2.4.1"},
        {"type": "library", "name": "faretensor", "version": "1.8.0"}]
    record("loaded at run time and missing from the inventory", [],
           not_in_inventory(loaded_now, inventory))
    drifted = [
        {"type": "model", "name": NAME, "digest": model_digest(deployed)},
        {"type": "adapter", "name": "refund-tone-adapter",
         "digest": sha256(canonical(list(adapter)))},
        {"type": "library", "name": "examplenet-runtime", "version": "2.4.1"},
        {"type": "library", "name": "faretensor", "version": "1.9.0"},
        {"type": "library", "name": "faretensor-utils", "version": "0.1.0"}]
    record("  after the adapter and the plain install",
           ["model exampleair/fare-model", "adapter refund-tone-adapter",
            "library faretensor 1.9.0", "library faretensor-utils 0.1.0"],
           not_in_inventory(drifted, inventory))
    record("inventory entries with no licence recorded",
           ["dataset refund-requests-2026q2"],
           [describe(c) for c in inventory if "licence" not in c])

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
