#!/usr/bin/env python3
"""Check the AEAD and KDF fixtures against an implementation outside zucrypt.

    python3 tools/check-kat.py

Maintainer tooling, never run at check time. Needs the `cryptography`
package for AES-GCM; PBKDF2 uses the standard library's hashlib. Both share
no code with the vendored backend, which is the point (design.md section
12): `openssl`'s R GCM returns no tag, so it cannot check one, and
tools/make-kat.R --check compares only what it can.

Every AEAD vector is encrypted, and its ciphertext and full tag compared;
then decrypted, and a flipped tag bit must fail. Every KDF vector is
recomputed. Exits non-zero on the first mismatch.
"""
import csv
import hashlib
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FIXTURES = os.path.join("tests", "testthat", "fixtures")


def rows(name):
    with open(os.path.join(FIXTURES, name), newline="") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def unhex(x):
    return bytes.fromhex(x) if x else b""


def fail(msg):
    sys.exit("check-kat: FAILED " + msg)


def check_aead():
    n = 0
    for r in rows("aead.tsv"):
        if r["algorithm"] != "aes-gcm":
            fail(f"{r['id']}: unknown algorithm {r['algorithm']}")
        g = AESGCM(unhex(r["key"]))
        aad = unhex(r["aad"]) or None
        out = g.encrypt(unhex(r["iv"]), unhex(r["input"]), aad)
        ct, tag = out[:-16], out[-16:]
        if ct.hex() != r["output"] or tag.hex() != r["tag"]:
            fail(f"{r['id']}: got {ct.hex()} / {tag.hex()}")
        pt = g.decrypt(unhex(r["iv"]), out, aad)
        if pt.hex() != r["input"]:
            fail(f"{r['id']}: decryption")
        bad = out[:-1] + bytes([out[-1] ^ 1])
        try:
            g.decrypt(unhex(r["iv"]), bad, aad)
            fail(f"{r['id']}: a flipped tag bit verified")
        except InvalidTag:
            pass
        n += 1
    return n


def check_kdf():
    n = 0
    for r in rows("kdf.tsv"):
        want = unhex(r["output"])
        got = hashlib.pbkdf2_hmac(r["algorithm"], unhex(r["password"]),
                                  unhex(r["salt"]), int(r["iterations"]),
                                  len(want))
        if got != want:
            fail(f"{r['id']}: got {got.hex()}")
        n += 1
    return n


if __name__ == "__main__":
    a = check_aead()
    k = check_kdf()
    print(f"check-kat: {a} AEAD and {k} KDF vectors match cryptography and hashlib.")
