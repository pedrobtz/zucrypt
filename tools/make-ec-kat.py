#!/usr/bin/env python3
"""Write, or check, the elliptic-curve known-answer fixtures (Stage 16a).

    python3 tools/make-ec-kat.py RFC6979.txt RFC7748.txt RFC5903.txt RFC7515.txt
    python3 tools/make-ec-kat.py --check

Maintainer tooling, never run at check time. Needs the `cryptography`
package (44 or later, for deterministic ECDSA).

Every vector is published, and extracted from the RFC texts given on the
command line, so writing again gives the same fixtures:

  - RFC 6979 A.2.5-A.2.7: deterministic ECDSA on P-256, P-384 and P-521,
    over the messages "sample" and "test", with SHA-1 and SHA-2 (r and s);
  - RFC 7748 section 6.1: X25519 key agreement;
  - RFC 5903 section 8: ECDH on P-256, P-384 and P-521;
  - RFC 7515 A.3 and A.4: ES256 and ES512 signatures (randomised, so
    verification only).

Writes tests/testthat/fixtures/ec-keys.tsv (each key: curve, d, x, y in
hex) and ec.tsv (one vector per row), and replaces its own rows in
MANIFEST.tsv. --check verifies every row with `cryptography`.
"""
import base64
import csv
import json
import os
import re
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, encode_dss_signature)

FIXTURES = os.path.join("tests", "testthat", "fixtures")
GENERATOR = "tools/make-ec-kat.py"
CURVES = {"P-256": (ec.SECP256R1, 32), "P-384": (ec.SECP384R1, 48),
          "P-521": (ec.SECP521R1, 66)}
HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256,
          "sha384": hashes.SHA384, "sha512": hashes.SHA512}


def lines_of(path):
    text = open(path, encoding="utf-8").read().replace("\f", "")
    furn = re.compile(r"^(\S.*\[Page \d+\]|RFC \d{4} .*)$")
    return [l for l in text.split("\n") if not furn.match(l)]


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hexpad(h, n):
    return h.lower().rjust(2 * n, "0")


def hex_after(lines, i):
    """Hex digits from line i (after an '=' or ':' if any) and the
    indented continuation lines that follow."""
    first = lines[i].split("=", 1)[-1] if "=" in lines[i] else ""
    out = re.sub(r"[^0-9A-Fa-f]", "", first)
    j = i + 1
    while j < len(lines) and re.fullmatch(r"\s+[0-9A-Fa-f ]+\s*", lines[j]):
        out += re.sub(r"\s", "", lines[j])
        j += 1
    return out


def rfc6979(path):
    lines = lines_of(path)
    keys, vectors = [], []
    for sec, curve in [("A.2.5.", "P-256"), ("A.2.6.", "P-384"),
                       ("A.2.7.", "P-521")]:
        n = CURVES[curve][1]
        start = next(i for i, l in enumerate(lines) if l.startswith(sec + "  "))
        end = next(i for i, l in enumerate(lines)
                   if i > start and re.match(r"^A\.\d", l))
        sec_lines = lines[start:end]

        def value(name, after=0):
            i = next(k for k in range(after, len(sec_lines))
                     if re.match(r"^\s+%s = " % name, sec_lines[k]))
            return hex_after(sec_lines, i), i

        d, _ = value("x")
        ux, _ = value("Ux")
        uy, _ = value("Uy")
        kid = "rfc6979-" + curve.lower().replace("-", "")
        keys.append({"id": kid, "curve": curve, "d": hexpad(d, n),
                     "x": hexpad(ux, n), "y": hexpad(uy, n)})
        for msg in ["sample", "test"]:
            for h in ["sha1", "sha256", "sha384", "sha512"]:
                label = 'With SHA-%s, message = "%s":' % (
                    "1" if h == "sha1" else h[3:], msg)
                i = next(k for k, l in enumerate(sec_lines) if label in l)
                r, _ = value("r", i)
                s, _ = value("s", i)
                vectors.append({
                    "id": "%s-%s-%s" % (kid, h, msg), "key": kid,
                    "peer": "", "operation": "sign-deterministic",
                    "hash": h, "input": msg.encode().hex(),
                    "output": hexpad(r, n) + hexpad(s, n),
                    "source": "RFC 6979 %s, SHA-%s, message %s" % (
                        sec.rstrip("."),
                        "1" if h == "sha1" else h[3:], msg)})
    return keys, vectors


def rfc7748(path):
    lines = lines_of(path)
    start = next(i for i, l in enumerate(lines) if l.startswith("6.1.  "))

    def val(label):
        i = next(k for k in range(start, len(lines)) if label in lines[k])
        return lines[i + 1].strip()

    a, A = val("Alice's private key, a:"), val("Alice's public key")
    b, B = val("Bob's private key, b:"), val("Bob's public key")
    K = val("Their shared secret, K:")
    keys = [{"id": "rfc7748-alice", "curve": "X25519", "d": a, "x": A, "y": ""},
            {"id": "rfc7748-bob", "curve": "X25519", "d": b, "x": B, "y": ""}]
    vectors = [{"id": "rfc7748-6.1", "key": "rfc7748-alice",
                "peer": "rfc7748-bob", "operation": "agree", "hash": "",
                "input": "", "output": K,
                "source": "RFC 7748 section 6.1 (X25519)"}]
    return keys, vectors


def rfc5903(path):
    lines = lines_of(path)
    keys, vectors = [], []
    for sec, curve in [("8.1.", "P-256"), ("8.2.", "P-384"),
                       ("8.3.", "P-521")]:
        n = CURVES[curve][1]
        start = next(i for i, l in enumerate(lines) if l.startswith(sec + "  "))

        def val(name):
            i = next(k for k in range(start, len(lines))
                     if lines[k].strip() == name + ":")
            return hex_after(lines, i)

        tag = "rfc5903-" + curve.lower().replace("-", "")
        keys.append({"id": tag + "-i", "curve": curve, "d": hexpad(val("i"), n),
                     "x": hexpad(val("gix"), n), "y": hexpad(val("giy"), n)})
        keys.append({"id": tag + "-r", "curve": curve, "d": hexpad(val("r"), n),
                     "x": hexpad(val("grx"), n), "y": hexpad(val("gry"), n)})
        vectors.append({"id": tag, "key": tag + "-i", "peer": tag + "-r",
                        "operation": "agree", "hash": "", "input": "",
                        "output": hexpad(val("girx"), n),
                        "source": "RFC 5903 section %s (ECDH %s)" % (
                            sec.rstrip("."), curve)})
    return keys, vectors


def rfc7515(path):
    lines = lines_of(path)
    keys, vectors = [], []
    for sec, nxt, curve, h in [("A.3.", "A.4.", "P-256", "sha256"),
                               ("A.4.", "A.5.", "P-521", "sha512")]:
        n = CURVES[curve][1]
        start = next(i for i, l in enumerate(lines) if l.startswith(sec + "  "))
        end = next(i for i, l in enumerate(lines)
                   if i > start and l.startswith(nxt + "  "))
        sl = lines[start:end]
        i = next(k for k, l in enumerate(sl) if '{"kty":"EC",' in l)
        j = next(k for k in range(i, len(sl)) if sl[k].strip() == "}")
        jwk = json.loads(re.sub(r"\s+", "", "".join(sl[i:j + 1])))
        i = next(k for k, l in enumerate(sl) if "JWS Signing Input value" in l)
        k = next(k for k in range(i, len(sl)) if sl[k].strip().startswith("["))
        body = []
        while True:
            body.append(sl[k])
            if "]" in sl[k]:
                break
            k += 1
        signing_input = bytes(int(x) for x in re.findall(r"\d+", " ".join(body)))
        i = next(k for k, l in enumerate(sl) if "value R || S" in l)
        k = next(k for k in range(i + 1, len(sl))
                 if re.fullmatch(r"\s+[A-Za-z0-9_-]+", sl[k]))
        sig = ""
        while k < len(sl) and re.fullmatch(r"\s+[A-Za-z0-9_-]+", sl[k]):
            sig += sl[k].strip()
            k += 1
        kid = "rfc7515-" + sec.rstrip(".").lower().replace(".", "")
        keys.append({"id": kid, "curve": curve,
                     "d": b64u(jwk["d"]).hex(), "x": b64u(jwk["x"]).hex(),
                     "y": b64u(jwk["y"]).hex()})
        vectors.append({"id": kid, "key": kid, "peer": "", "operation": "verify",
                        "hash": h, "input": signing_input.hex(),
                        "output": b64u(sig).hex(),
                        "source": "RFC 7515 %s (ES%s signature)" % (
                            sec.rstrip("."), "256" if h == "sha256" else "512")})
    return keys, vectors


def write(p6979, p7748, p5903, p7515):
    keys, vectors = [], []
    for k, v in [rfc6979(p6979), rfc7748(p7748), rfc5903(p5903),
                 rfc7515(p7515)]:
        keys += k
        vectors += v
    with open(os.path.join(FIXTURES, "ec-keys.tsv"), "w", newline="") as f:
        w = csv.DictWriter(f, ["id", "curve", "d", "x", "y"], delimiter="\t",
                           lineterminator="\n")
        w.writeheader()
        w.writerows(keys)
    cols = ["id", "key", "peer", "operation", "hash", "input", "output"]
    with open(os.path.join(FIXTURES, "ec.tsv"), "w", newline="") as f:
        w = csv.DictWriter(f, cols, delimiter="\t", lineterminator="\n",
                           extrasaction="ignore")
        w.writeheader()
        w.writerows(vectors)
    path = os.path.join(FIXTURES, "MANIFEST.tsv")
    rows = [r for r in csv.DictReader(open(path), delimiter="\t")
            if r["file"] not in ("ec.tsv", "ec-keys.tsv")]
    rows += [{"file": "ec-keys.tsv", "id": k["id"],
              "source": next(v["source"] for v in vectors
                             if k["id"] in (v["key"], v["peer"])),
              "generator": GENERATOR} for k in keys]
    rows += [{"file": "ec.tsv", "id": v["id"], "source": v["source"],
              "generator": GENERATOR} for v in vectors]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, ["file", "id", "source", "generator"],
                           delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print("wrote %d keys and %d vectors" % (len(keys), len(vectors)))


def private(k):
    if k["curve"] == "X25519":
        return x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(k["d"]))
    key = ec.derive_private_key(int(k["d"], 16), CURVES[k["curve"]][0]())
    nums = key.public_key().public_numbers()
    n = CURVES[k["curve"]][1]
    if (format(nums.x, "x").rjust(2 * n, "0"),
            format(nums.y, "x").rjust(2 * n, "0")) != (k["x"], k["y"]):
        sys.exit("make-ec-kat: FAILED key %s: d does not give x, y" % k["id"])
    return key


def check():
    keys = {r["id"]: r for r in csv.DictReader(
        open(os.path.join(FIXTURES, "ec-keys.tsv")), delimiter="\t")}
    n = 0
    for v in csv.DictReader(open(os.path.join(FIXTURES, "ec.tsv")),
                            delimiter="\t"):
        k = keys[v["key"]]
        key = private(k)
        out = bytes.fromhex(v["output"])
        if v["operation"] == "agree":
            peer = private(keys[v["peer"]]).public_key()
            got = (key.exchange(peer) if k["curve"] == "X25519"
                   else key.exchange(ec.ECDH(), peer))
            ok = got == out
        else:
            half = CURVES[k["curve"]][1]
            der = encode_dss_signature(int.from_bytes(out[:half], "big"),
                                       int.from_bytes(out[half:], "big"))
            data = bytes.fromhex(v["input"])
            hc = HASHES[v["hash"]]
            key.public_key().verify(der, data, ec.ECDSA(hc()))
            ok = True
            if v["operation"] == "sign-deterministic":
                again = key.sign(data, ec.ECDSA(hc(), deterministic_signing=True))
                r, s = decode_dss_signature(again)
                ok = (r.to_bytes(half, "big") + s.to_bytes(half, "big")) == out
        if not ok:
            sys.exit("make-ec-kat: FAILED " + v["id"])
        n += 1
    print("make-ec-kat: %d EC vectors verify with cryptography." % n)


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif len(sys.argv) == 5:
        write(*sys.argv[1:])
    else:
        sys.exit(__doc__)
