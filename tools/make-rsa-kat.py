#!/usr/bin/env python3
"""Write, or check, the RSA known-answer fixtures (Stage 15a).

    python3 tools/make-rsa-kat.py RFC7515.txt RFC7516.txt   write the fixtures
    python3 tools/make-rsa-kat.py --limits                  (re)write the limit rows
    python3 tools/make-rsa-kat.py --check                   check them

Maintainer tooling, never run at check time. Needs the `cryptography`
package.

Writes tests/testthat/fixtures/rsa-keys.tsv (each key as its integers, in
hex) and rsa.tsv (one vector per row), and appends their rows to
MANIFEST.tsv. Two kinds of vector:

  - published, extracted from the RFC texts given on the command line:
    RFC 7515 A.2 (an RSASSA-PKCS1-v1_5 SHA-256 signature, deterministic),
    RFC 7516 A.1 (an RSAES-OAEP encrypted key) and A.2 (an
    RSAES-PKCS1-v1_5 encrypted key);
  - generated with `cryptography`, for what no RFC publishes: PSS
    signatures and OAEP ciphertexts over SHA-256, SHA-384 and SHA-512, on
    one generated 2048-bit key. Their source says so;
  - the message-length limits (#102), also generated: on that key, for
    PKCS#1 v1.5 (k - 11) and OAEP with each hash (k - 2 hLen - 2), a
    ciphertext of a message at the limit and one byte under it.
    --limits rewrites only these rows, for the key already committed.

PSS and OAEP are randomised, so writing again generates new values. --check
does not regenerate: it verifies every row with `cryptography` -- each
signature verifies, each ciphertext decrypts to its plaintext, and the
deterministic signature is reproduced -- and exits non-zero on the first
failure.
"""
import csv
import json
import os
import re
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

FIXTURES = os.path.join("tests", "testthat", "fixtures")
KEY_FIELDS = ["n", "e", "d", "p", "q", "dp", "dq", "qi"]
HASHES = {"sha1": hashes.SHA1, "sha256": hashes.SHA256,
          "sha384": hashes.SHA384, "sha512": hashes.SHA512}
GENERATOR = "tools/make-rsa-kat.py"


def b64u_int(s):
    import base64
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    return int.from_bytes(raw, "big")


def hexint(i):
    h = format(i, "x")
    return ("0" if len(h) % 2 else "") + h


def text_lines(path):
    lines = open(path, encoding="utf-8").read().replace("\f", "").split("\n")
    furniture = re.compile(r"^(Jones|RFC 751[56]) ")
    return [l for l in lines if not furniture.match(l)]


def section(lines, start, end):
    i = next(k for k, l in enumerate(lines) if l.startswith(start))
    j = next(k for k, l in enumerate(lines) if k > i and l.startswith(end))
    return lines[i:j]


def jwk(lines):
    i = next(k for k, l in enumerate(lines) if '{"kty":"RSA",' in l)
    j = next(k for k in range(i, len(lines)) if lines[k].strip() == "}")
    return json.loads(re.sub(r"\s+", "", "".join(lines[i:j + 1])))


def byte_array_after(lines, marker):
    i = next(k for k, l in enumerate(lines) if marker in l)
    k = next(k for k in range(i, len(lines)) if lines[k].strip().startswith("["))
    body = []
    while True:
        body.append(lines[k])
        if "]" in lines[k]:
            break
        k += 1
    return bytes(int(x) for x in re.findall(r"\d+", " ".join(body)))


def key_row(kid, jwk_obj):
    return {"id": kid, **{f: hexint(b64u_int(jwk_obj[f])) for f in KEY_FIELDS}}


def private_key(row):
    n, e, d, p, q, dp, dq, qi = (int(row[f], 16) for f in KEY_FIELDS)
    return rsa.RSAPrivateNumbers(
        p, q, d, dp, dq, qi, rsa.RSAPublicNumbers(e, n)).private_key()


LIMIT_PREFIX = "rsa-limit-"


def limit_vectors(key, key_id):
    """Ciphertexts at each padding's longest message and one byte under."""
    k = key.key_size // 8
    pub = key.public_key()
    version = __import__("cryptography").__version__
    out = []
    for scheme, h in [("pkcs1v15", ""), ("oaep", "sha1"), ("oaep", "sha256"),
                      ("oaep", "sha384"), ("oaep", "sha512")]:
        if scheme == "oaep":
            hc = HASHES[h]
            limit = k - 2 * hc.digest_size - 2
            pad = padding.OAEP(mgf=padding.MGF1(hc()), algorithm=hc(),
                               label=None)
        else:
            limit = k - 11
            pad = padding.PKCS1v15()
        for n in (limit - 1, limit):
            msg = bytes((7 * i + n) % 256 for i in range(n))
            out.append({
                "id": "%s%s-%s-%d" % (LIMIT_PREFIX, scheme, h or "none", n),
                "key": key_id, "operation": "decrypt", "scheme": scheme,
                "hash": h, "input": msg.hex(),
                "output": pub.encrypt(msg, pad).hex(),
                "source": "Python cryptography %s, generated: a %d-byte "
                          "message, %s the %s limit (#102)" % (
                              version, n,
                              "at" if n == limit else "one byte under",
                              scheme + ("-" + h if h else ""))})
    return out


def write_vectors(vectors, keys):
    cols = ["id", "key", "operation", "scheme", "hash", "input", "output"]
    with open(os.path.join(FIXTURES, "rsa.tsv"), "w", newline="") as f:
        w = csv.DictWriter(f, cols, delimiter="\t", lineterminator="\n",
                           extrasaction="ignore")
        w.writeheader()
        w.writerows(vectors)

    # MANIFEST.tsv is shared: keep the other generators' rows, and put ours
    # back where they were (make-wycheproof.py --check expects its own last).
    path = os.path.join(FIXTURES, "MANIFEST.tsv")
    ours = ("rsa.tsv", "rsa-keys.tsv")
    old = list(csv.DictReader(open(path), delimiter="\t"))
    at = next((i for i, r in enumerate(old) if r["file"] in ours), len(old))
    rows = [r for r in old[:at] if r["file"] not in ours]
    rows += [{"file": "rsa-keys.tsv", "id": k["id"],
              "source": k.get("source") or next(
                  (v["source"] for v in vectors if v["key"] == k["id"]), ""),
              "generator": GENERATOR} for k in keys]
    rows += [{"file": "rsa.tsv", "id": v["id"], "source": v["source"],
              "generator": GENERATOR} for v in vectors]
    rows += [r for r in old[at:] if r["file"] not in ours]
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, ["file", "id", "source", "generator"],
                           delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def limits():
    """Replace the limit rows, keeping every other row and the keys."""
    keys = list(csv.DictReader(
        open(os.path.join(FIXTURES, "rsa-keys.tsv")), delimiter="\t"))
    manifest = {(r["file"], r["id"]): r["source"] for r in csv.DictReader(
        open(os.path.join(FIXTURES, "MANIFEST.tsv")), delimiter="\t")}
    for k in keys:
        k["source"] = manifest.get(("rsa-keys.tsv", k["id"]), "")
    vectors = [dict(v, source=manifest[("rsa.tsv", v["id"])])
               for v in csv.DictReader(
                   open(os.path.join(FIXTURES, "rsa.tsv")), delimiter="\t")
               if not v["id"].startswith(LIMIT_PREFIX)]
    gen = next(k for k in keys if k["id"] == "generated-2048")
    vectors += limit_vectors(private_key(gen), "generated-2048")
    write_vectors(vectors, keys)
    print("wrote %d vectors" % len(vectors))


def write(rfc7515, rfc7516):
    keys, vectors, manifest = [], [], []

    a2 = section(text_lines(rfc7515), "A.2.  Example JWS Using RSASSA",
                 "A.3.  Example JWS Using ECDSA")
    keys.append(key_row("rfc7515-a2", jwk(a2)))
    vectors.append({
        "id": "rsa-rfc7515-a2", "key": "rfc7515-a2", "operation": "sign",
        "scheme": "pkcs1v15", "hash": "sha256",
        "input": byte_array_after(a2, "JWS Signing Input value").hex(),
        "output": byte_array_after(a2, "In this example, it is:").hex(),
        "source": "RFC 7515 A.2 (RS256 signature)"})

    lines16 = text_lines(rfc7516)
    for label, start, end, scheme, hash_ in [
        ("a1", "A.1.  Example JWE using RSAES-OAEP",
         "A.2.  Example JWE using RSAES-PKCS1", "oaep", "sha1"),
        ("a2", "A.2.  Example JWE using RSAES-PKCS1",
         "A.3.  Example JWE Using AES Key Wrap", "pkcs1v15", ""),
    ]:
        sec = section(lines16, start, end)
        kid = "rfc7516-" + label
        keys.append(key_row(kid, jwk(sec)))
        vectors.append({
            "id": "rsa-" + kid, "key": kid, "operation": "decrypt",
            "scheme": scheme, "hash": hash_,
            "input": byte_array_after(sec, "Content Encryption Key").hex(),
            "output": byte_array_after(sec, "Encrypted Key value is").hex(),
            "source": "RFC 7516 %s (%s encrypted CEK)" % (
                label.upper().replace("A", "A."),
                "RSAES-OAEP" if scheme == "oaep" else "RSAES-PKCS1-v1_5")})

    gen = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    nums = gen.private_numbers()
    keys.append({"id": "generated-2048", **{
        "n": hexint(nums.public_numbers.n), "e": hexint(nums.public_numbers.e),
        "d": hexint(nums.d), "p": hexint(nums.p), "q": hexint(nums.q),
        "dp": hexint(nums.dmp1), "dq": hexint(nums.dmq1),
        "qi": hexint(nums.iqmp)}})
    message = b"zucrypt RSA known answer"
    for h in ["sha256", "sha384", "sha512"]:
        hc = HASHES[h]
        sig = gen.sign(message, padding.PSS(
            mgf=padding.MGF1(hc()), salt_length=hc.digest_size), hc())
        vectors.append({
            "id": "rsa-pss-" + h, "key": "generated-2048",
            "operation": "verify", "scheme": "pss", "hash": h,
            "input": message.hex(), "output": sig.hex(),
            "source": "Python cryptography %s, generated (no published vector)"
                      % __import__("cryptography").__version__})
        secret = bytes(range(32))
        ct = gen.public_key().encrypt(secret, padding.OAEP(
            mgf=padding.MGF1(hc()), algorithm=hc(), label=None))
        vectors.append({
            "id": "rsa-oaep-" + h, "key": "generated-2048",
            "operation": "decrypt", "scheme": "oaep", "hash": h,
            "input": secret.hex(), "output": ct.hex(),
            "source": "Python cryptography %s, generated (no published vector)"
                      % __import__("cryptography").__version__})
    vectors += limit_vectors(gen, "generated-2048")

    with open(os.path.join(FIXTURES, "rsa-keys.tsv"), "w", newline="") as f:
        w = csv.DictWriter(f, ["id"] + KEY_FIELDS, delimiter="\t",
                           lineterminator="\n")
        w.writeheader()
        w.writerows(keys)
    write_vectors(vectors, keys)
    print("wrote %d keys and %d vectors" % (len(keys), len(vectors)))


def check():
    keys = {r["id"]: r for r in csv.DictReader(
        open(os.path.join(FIXTURES, "rsa-keys.tsv")), delimiter="\t")}
    n = 0
    for v in csv.DictReader(open(os.path.join(FIXTURES, "rsa.tsv")),
                            delimiter="\t"):
        key = private_key(keys[v["key"]])
        data, out = bytes.fromhex(v["input"]), bytes.fromhex(v["output"])
        hc = HASHES.get(v["hash"])
        if v["scheme"] == "pkcs1v15" and v["operation"] == "sign":
            ok = key.sign(data, padding.PKCS1v15(), hc()) == out
        elif v["scheme"] == "pss":
            key.public_key().verify(out, data, padding.PSS(
                mgf=padding.MGF1(hc()), salt_length=hc.digest_size), hc())
            ok = True
        elif v["scheme"] == "oaep":
            ok = key.decrypt(out, padding.OAEP(
                mgf=padding.MGF1(hc()), algorithm=hc(), label=None)) == data
        else:
            ok = key.decrypt(out, padding.PKCS1v15()) == data
        if not ok:
            sys.exit("make-rsa-kat: FAILED " + v["id"])
        n += 1
    print("make-rsa-kat: %d RSA vectors verify with cryptography." % n)


if __name__ == "__main__":
    if sys.argv[1:] == ["--check"]:
        check()
    elif sys.argv[1:] == ["--limits"]:
        limits()
    elif len(sys.argv) == 3:
        write(sys.argv[1], sys.argv[2])
    else:
        sys.exit(__doc__)
