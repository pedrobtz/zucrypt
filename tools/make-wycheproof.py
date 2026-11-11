#!/usr/bin/env python3
"""Project Wycheproof vectors for zucrypt (#70).

Wycheproof (github.com/C2SP/wycheproof) collects test vectors for known
attacks and edge cases: each case says whether a correct implementation
must accept it ("valid"), must reject it ("invalid"), or may do either
("acceptable"), with flags naming what it probes. Where NIST's CAVP vectors
(tools/make-cavp.py) check that the answer is right, these check that the
wrong inputs are refused: modified tags, malleable and malformed signatures,
low-order points, padding oracles.

This script fetches the files below at a pinned commit, checks each against
its SHA-256, and flattens the cases zucrypt can express into one table:

    tools/wycheproof/wycheproof.tsv.gz   every usable case (kept out of the
                                         tarball; test-wycheproof.R runs it
                                         when ZUCRYPT_WYCHEPROOF names it)
    tests/testthat/fixtures/wycheproof.tsv
                                         the shipped subset: for each family,
                                         result and flag set, its first case,
                                         with its MANIFEST.tsv provenance row

Cases zucrypt cannot express are left out and counted: AES-GCM with a nonce
other than 96 bits or a tag other than 128 (the R functions take exactly
those), and OAEP with a non-empty label. Columns: family, file, tc_id,
result, flags, hash, key, iv, aad, msg, ct, tag, all hex but the first six.
For signatures `ct` is the signature; for ECDH and X25519 `key` is the
private key (for ECDH the scalar, an ASN.1 INTEGER's bytes), `msg` the
peer's public key (for ECDH SubjectPublicKeyInfo DER) and `ct` the shared
secret, and for ECDH `hash` names the curve.

    python3 tools/make-wycheproof.py [--check]
"""
import gzip
import hashlib
import json
import os
import sys
import urllib.request

COMMIT = "a3d5d1423f2592d6646836a45a21a1b209da9f4d"  # 2026-10-23
BASE = f"https://raw.githubusercontent.com/C2SP/wycheproof/{COMMIT}/testvectors_v1/"

# file -> (family, sha256 of the file at COMMIT)
FILES = {
    "aes_gcm_test.json": ("gcm", "985e5ecc172e181eaf49e89508b9470dcf478002eb7e8559c707eb42dc97dfe7"),
    "hmac_sha1_test.json": ("hmac", "b521c6180a862247986392d3cb49b511fc7fe790e75bee236f84e36ca290c7c0"),
    "hmac_sha256_test.json": ("hmac", "2d201cfa61d1bf95e6f5d07d96634b4a348b31e8eaa277ad7c8d09677b7a743f"),
    "hmac_sha384_test.json": ("hmac", "28b9776e979dd755d852ca471043ea6cedce8b15f7a28abdf6ea9efd982b43c0"),
    "hmac_sha512_test.json": ("hmac", "b6c90477bdb4a6fc8ee3d1f7b2c0b69a8dfffab34718abaa6cabd71cc2ba1207"),
    "ecdsa_secp256r1_sha256_test.json": ("ecdsa", "182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332"),
    "ecdsa_secp384r1_sha384_test.json": ("ecdsa", "8a5b3ae1760975143414811f13588c24d951d9d8c904195087ba327591dfe9cc"),
    "ecdsa_secp521r1_sha512_test.json": ("ecdsa", "0fa3bb09a2319242253028b53d555fb8ec2081d891271321205cdaeabb3eef3e"),
    "rsa_signature_2048_sha256_test.json": ("rsa-pkcs1-sig", "94a917b01ff50fb874cfc05bf29b4af44868d944a6558201cf18380da93fb393"),
    "rsa_pss_2048_sha256_mgf1_32_test.json": ("rsa-pss", "7f6efafc160f4816b96cbf1c12188a31051d7e3f001e27505d9edb5f2a0e325c"),
    "rsa_oaep_2048_sha1_mgf1sha1_test.json": ("rsa-oaep", "2c7b3694cd9265eb88ddb586ca29aefcea02938bde772e19a71a4fa601fc71c5"),
    "rsa_oaep_2048_sha256_mgf1sha256_test.json": ("rsa-oaep", "83dce701e3d8640ac56e6d7bf37a5a8f9bd6a336e1e932a1e9bfe4ba9c5ea3a9"),
    "rsa_pkcs1_2048_test.json": ("rsa-pkcs1-crypt", "28466c4390f1f8943754a990ba36397ebbac628117d91b57f87e1ba200b932f3"),
    "ecdh_secp256r1_test.json": ("ecdh", "cdb8bd5d1206fddb6618c69ffa18f303b4752caba321d348d4aacae3f20cbec4"),
    "ecdh_secp384r1_test.json": ("ecdh", "25a9c41573dbea97c5b4be2dd00369fa68dc37ac8f41807d8e16226d188ec6a7"),
    "ecdh_secp521r1_test.json": ("ecdh", "b5e379919833afa94ef6cb7e085367408a5ea63cf486ad008ad36ef9be4bebf0"),
    "x25519_test.json": ("x25519", "35c3f5231cf25cc640b524d403461deee9e49441d5d915a3a25b2c8ff5adbe7d"),
}

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FULL = os.path.join(ROOT, "tools", "wycheproof", "wycheproof.tsv.gz")
SHIPPED = os.path.join(ROOT, "tests", "testthat", "fixtures", "wycheproof.tsv")
CACHE = os.path.join(ROOT, "tools", "wycheproof", "cache")
MANIFEST = os.path.join(ROOT, "tests", "testthat", "fixtures", "MANIFEST.tsv")
GENERATOR = "tools/make-wycheproof.py"
COLUMNS = ["family", "file", "tc_id", "result", "flags", "hash", "key", "iv",
           "aad", "msg", "ct", "tag"]

HASHES = {"SHA-1": "sha1", "SHA-256": "sha256", "SHA-384": "sha384",
          "SHA-512": "sha512"}


def fetch(name):
    os.makedirs(CACHE, exist_ok=True)
    path = os.path.join(CACHE, name)
    if not os.path.exists(path):
        with urllib.request.urlopen(BASE + name) as r, open(path, "wb") as f:
            f.write(r.read())
    data = open(path, "rb").read()
    want = FILES[name][1]
    got = hashlib.sha256(data).hexdigest()
    if want and got != want:
        sys.exit(f"{name}: sha256 {got}, pinned {want}")
    return json.loads(data), got


def rows_for(name, doc):
    family = FILES[name][0]
    out, skipped = [], 0
    for g in doc["testGroups"]:
        for t in g["tests"]:
            row = dict.fromkeys(COLUMNS, "")
            row.update(family=family, file=name, tc_id=str(t["tcId"]),
                       result=t["result"], flags=",".join(t.get("flags", [])))
            if family == "gcm":
                if g["ivSize"] != 96 or g["tagSize"] != 128:
                    skipped += 1
                    continue
                row.update(key=t["key"], iv=t["iv"], aad=t["aad"],
                           msg=t["msg"], ct=t["ct"], tag=t["tag"])
            elif family == "hmac":
                row.update(hash=name.split("_")[1], key=t["key"],
                           msg=t["msg"], tag=t["tag"])
            elif family in ("ecdsa", "rsa-pkcs1-sig", "rsa-pss"):
                row.update(hash=HASHES[g["sha"]], key=g["publicKeyDer"],
                           msg=t["msg"], ct=t["sig"])
            elif family == "rsa-oaep":
                if t.get("label", ""):
                    skipped += 1
                    continue
                row.update(hash=HASHES[g["sha"]], key=g["privateKeyPkcs8"],
                           msg=t["msg"], ct=t["ct"])
            elif family == "rsa-pkcs1-crypt":
                row.update(key=g["privateKeyPkcs8"], msg=t["msg"], ct=t["ct"])
            elif family == "ecdh":
                curve = {"secp256r1": "p256", "secp384r1": "p384",
                         "secp521r1": "p521"}[g["curve"]]
                row.update(hash=curve, key=t["private"], msg=t["public"],
                           ct=t["shared"])
            elif family == "x25519":
                row.update(key=t["private"], msg=t["public"], ct=t["shared"])
            out.append(row)
    return out, skipped


def subset(rows):
    seen, out = set(), []
    for r in rows:
        k = (r["family"], r["hash"], r["result"], r["flags"])
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def case_id(r):
    return "wp-" + r["file"].replace("_test.json", "").replace("_", "-") + \
        "-" + r["tc_id"]


def manifest(sub):
    """MANIFEST.tsv with this generator's rows replaced; the others kept."""
    with open(MANIFEST, encoding="ascii") as f:
        lines = f.read().splitlines()
    header, body = lines[0], lines[1:]
    body = [l for l in body if l.split("\t")[3] != GENERATOR]
    body += [f"wycheproof.tsv\t{case_id(r)}\tProject Wycheproof {COMMIT[:7]} "
             f"testvectors_v1/{r['file']} tcId {r['tc_id']} ({r['result']})"
             f"\t{GENERATOR}" for r in sub]
    return "\n".join([header] + body) + "\n"


def tsv(rows):
    lines = ["\t".join(COLUMNS)]
    lines += ["\t".join(r[c] for c in COLUMNS) for r in rows]
    return "\n".join(lines) + "\n"


def main():
    rows, pins = [], {}
    for name in FILES:
        doc, sha = fetch(name)
        pins[name] = sha
        got, skipped = rows_for(name, doc)
        rows += got
        print(f"{name}: {len(got)} cases, {skipped} not expressible")
    if not all(v[1] for v in FILES.values()):
        print("pins:")
        for name, sha in pins.items():
            print(f'    "{name}": ("{FILES[name][0]}", "{sha}"),')
        sys.exit("fill in the pins above, then run again")
    full, shipped = tsv(rows), tsv(subset(rows))
    man = manifest(subset(rows))
    print(f"{len(rows)} cases, {len(subset(rows))} shipped")
    if "--check" in sys.argv:
        old_full = gzip.open(FULL, "rt").read() if os.path.exists(FULL) else ""
        old_shipped = open(SHIPPED).read() if os.path.exists(SHIPPED) else ""
        if old_full != full or old_shipped != shipped or \
                open(MANIFEST).read() != man:
            sys.exit("make-wycheproof --check: the fixtures or MANIFEST.tsv differ")
        print("make-wycheproof --check: the fixtures and MANIFEST.tsv match")
        return
    os.makedirs(os.path.dirname(FULL), exist_ok=True)
    with gzip.GzipFile(FULL, "wb", mtime=0) as f:
        f.write(full.encode())
    with open(SHIPPED, "w") as f:
        f.write(shipped)
    with open(MANIFEST, "w") as f:
        f.write(man)
    print(f"wrote {FULL} and {SHIPPED}")


if __name__ == "__main__":
    main()
