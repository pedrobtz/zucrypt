#!/usr/bin/env python3
"""NIST CAVP vectors for SHA, HMAC and AES-CBC, as zucrypt fixtures (#67).

Fetches the CAVP response archives by URL, checks each against the SHA-256
recorded below, and converts the .rsp files for what zucrypt enables
(SHA-1, SHA-256, SHA-384, SHA-512; HMAC over those four; AES-CBC at 128, 192
and 256 bits) into the kat.tsv column layout:

    id  family  algorithm  key  iv  input  output

Families: hash (ShortMsg, LongMsg), hash-monte (SHAVS Monte: input is the
checkpoint's seed, that is the previous checkpoint's digest), hmac (output is
the tag, truncated to Tlen as the file lists it), cbc (GFSbox, KeySbox,
VarKey, VarTxt, MMT; algorithm is "encrypt" or "decrypt", input and output
in that direction), cbc-mct (AESAVS Monte Carlo, one row per COUNT with the
start values the file lists for it).

It writes two files:

- tools/cavp/cavp.tsv.gz, every vector (kept out of the tarball;
  tests/testthat/test-cavp.R runs it when ZUCRYPT_CAVP names the file, which
  aes-paths.yaml and tools/ci/platform.sh do);
- tests/testthat/fixtures/cavp.tsv, the shipped subset, with its rows in
  fixtures/MANIFEST.tsv. Rows other generators own are kept.

CAVP is itself the outside oracle; nothing is recomputed. --check rebuilds
both files in memory and fails if either differs from the committed bytes.

    python3 tools/make-cavp.py [--cache DIR] [--check]
"""
import argparse
import gzip
import hashlib
import io
import os
import re
import sys
import tempfile
import urllib.request
import zipfile

BASE = ("https://csrc.nist.gov/CSRC/media/Projects/"
        "Cryptographic-Algorithm-Validation-Program/documents/")
ARCHIVES = {
    "shabytetestvectors.zip": (
        "shs/shabytetestvectors.zip",
        "929ef80b7b3418aca026643f6f248815913b60e01741a44bba9e118067f4c9b8"),
    "hmactestvectors.zip": (
        "mac/hmactestvectors.zip",
        "418c3837d38f249d6668146bd0090db24dd3c02d2e6797e3de33860a387ae4bd"),
    "KAT_AES.zip": (
        "aes/KAT_AES.zip",
        "a203b16c9246b2ebae31dee5de21a606be80cf78ceabaca37150236fa098eb60"),
    "aesmmt.zip": (
        "aes/aesmmt.zip",
        "12d1616f7a713e807714055973f04efc402f46a14e3d81869717c7ace4ecbaf0"),
    "aesmct.zip": (
        "aes/aesmct.zip",
        "6a2a72c00b1daacb9a7d20ab92617d322fa1c5dee493968660990e3f4571426b"),
}
SHA = {"SHA1": "sha1", "SHA256": "sha256", "SHA384": "sha384",
       "SHA512": "sha512"}
HMAC_L = {20: "sha1", 32: "sha256", 48: "sha384", 64: "sha512"}
COLUMNS = ["id", "family", "algorithm", "key", "iv", "input", "output"]

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FULL = os.path.join(ROOT, "tools", "cavp", "cavp.tsv.gz")
FIXTURES = os.path.join(ROOT, "tests", "testthat", "fixtures")
SUBSET = os.path.join(FIXTURES, "cavp.tsv")
MANIFEST = os.path.join(FIXTURES, "MANIFEST.tsv")
GENERATOR = "tools/make-cavp.py"


def fetch(cache):
    out = {}
    for name, (path, want) in ARCHIVES.items():
        local = os.path.join(cache, name)
        if not os.path.exists(local):
            with urllib.request.urlopen(BASE + path) as r, \
                    open(local, "wb") as f:
                f.write(r.read())
        with open(local, "rb") as f:
            data = f.read()
        got = hashlib.sha256(data).hexdigest()
        if got != want:
            sys.exit(f"{name}: SHA-256 {got}, expected {want}")
        out[name] = zipfile.ZipFile(io.BytesIO(data))
    return out


def rsp(archive, base):
    """The named .rsp from an archive, wherever it sits in the tree."""
    names = [n for n in archive.namelist() if n.split("/")[-1] == base]
    if len(names) != 1:
        sys.exit(f"{base}: {len(names)} matches")
    return archive.read(names[0]).decode("ascii")


def records(text):
    """(section, {field: value}) per blank-line-separated record."""
    section, rec = None, {}
    for line in text.splitlines() + [""]:
        line = line.strip()
        if line.startswith("#"):
            continue
        m = re.fullmatch(r"\[(.*)\]", line)
        if m:
            section = m.group(1).replace(" ", "")
            continue
        if not line:
            if rec:
                yield section, rec
                rec = {}
            continue
        k, _, v = line.partition("=")
        rec[k.strip()] = v.strip().lower()


def row(id_, family, alg, key="", iv="", inp="", out=""):
    return dict(zip(COLUMNS, [id_, family, alg, key, iv, inp, out]))


def sha_rows(z):
    rows = []
    for stem, alg in SHA.items():
        for kind in ("ShortMsg", "LongMsg"):
            f = f"{stem}{kind}.rsp"
            for _, r in records(rsp(z, f)):
                if "Len" not in r:
                    continue
                bits = int(r["Len"])
                msg = r["Msg"][: bits // 4]  # Len = 0 lists Msg = 00
                rows.append(row(f"cavp-{stem}{kind}-{bits:06d}", "hash", alg,
                                inp=msg, out=r["MD"]))
        f = f"{stem}Monte.rsp"
        text = rsp(z, f)
        seed = re.search(r"Seed = ([0-9a-fA-F]+)", text).group(1).lower()
        for _, r in records(text):
            if "COUNT" not in r:
                continue
            n = int(r["COUNT"])
            rows.append(row(f"cavp-{stem}Monte-{n:03d}", "hash-monte", alg,
                            inp=seed, out=r["MD"]))
            seed = r["MD"]
    return rows


def hmac_rows(z):
    rows = []
    for section, r in records(rsp(z, "HMAC.rsp")):
        L = int(section.split("=")[1])
        if L not in HMAC_L or "Count" not in r:
            continue
        tlen = int(r["Tlen"])
        assert len(r["Mac"]) == 2 * tlen and len(r["Key"]) == 2 * int(r["Klen"])
        rows.append(row(f"cavp-HMAC-L{L}-{int(r['Count']):03d}", "hmac",
                        HMAC_L[L], key=r["Key"], inp=r["Msg"], out=r["Mac"]))
    return rows


def cbc_rows(kat, mmt, mct):
    rows = []
    for bits in (128, 192, 256):
        files = [(kat, f"CBC{t}{bits}.rsp", "cbc")
                 for t in ("GFSbox", "KeySbox", "VarKey", "VarTxt")]
        files += [(mmt, f"CBCMMT{bits}.rsp", "cbc"),
                  (mct, f"CBCMCT{bits}.rsp", "cbc-mct")]
        for z, f, family in files:
            stem = f[:-4]
            for section, r in records(rsp(z, f)):
                if "COUNT" not in r:
                    continue
                enc = section == "ENCRYPT"
                pt, ct = r["PLAINTEXT"], r["CIPHERTEXT"]
                rows.append(row(
                    f"cavp-{stem}-{'enc' if enc else 'dec'}-{int(r['COUNT']):03d}",
                    family, "encrypt" if enc else "decrypt", key=r["KEY"],
                    iv=r["IV"], inp=pt if enc else ct, out=ct if enc else pt))
    return rows


def subset(rows):
    """What ships: SHA-256 ShortMsg whole, two Monte checkpoints per digest,
    each HMAC (digest, key length, tag length) once, the AES-256 CBC MMT
    whole, and two Monte checkpoints per key size and direction, so the
    shipped set crosses a key update."""
    keep, seen = [], set()
    for r in rows:
        i = r["id"]
        if i.startswith("cavp-SHA256ShortMsg-") or i.startswith("cavp-CBCMMT256-"):
            keep.append(r)
        elif r["family"] == "hash-monte" and int(i[-3:]) < 2:
            keep.append(r)
        elif r["family"] == "cbc-mct" and int(i[-3:]) < 2:
            keep.append(r)
        elif r["family"] == "hmac":
            sig = (r["algorithm"], len(r["key"]), len(r["output"]))
            if sig not in seen:
                seen.add(sig)
                keep.append(r)
    return keep


def tsv(rows):
    lines = ["\t".join(COLUMNS)]
    lines += ["\t".join(r[c] for c in COLUMNS) for r in rows]
    return ("\n".join(lines) + "\n").encode("ascii")


def source(r):
    i = r["id"]
    if r["family"].startswith("hash"):
        return "NIST CAVP SHAVS, shabytetestvectors.zip " + i[5:].rsplit("-", 1)[0] + ".rsp"
    if r["family"] == "hmac":
        return "NIST CAVP HMACVS, hmactestvectors.zip HMAC.rsp"
    stem = i[5:].split("-")[0]
    archive = ("aesmct.zip" if "MCT" in stem else
               "aesmmt.zip" if "MMT" in stem else "KAT_AES.zip")
    return f"NIST CAVP AESAVS, {archive} {stem}.rsp"


def manifest(sub):
    with open(MANIFEST, encoding="ascii") as f:
        lines = f.read().splitlines()
    header, body = lines[0], lines[1:]
    body = [l for l in body if l.split("\t")[3] != GENERATOR]
    body += [f"cavp.tsv\t{r['id']}\t{source(r)}\t{GENERATOR}" for r in sub]
    return ("\n".join([header] + body) + "\n").encode("ascii")


def gz(data):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0, filename="") as g:
        g.write(data)
    return buf.getvalue()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cache", default=None)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    cache = a.cache or tempfile.mkdtemp(prefix="cavp-")
    os.makedirs(cache, exist_ok=True)
    z = fetch(cache)
    rows = (sha_rows(z["shabytetestvectors.zip"]) +
            hmac_rows(z["hmactestvectors.zip"]) +
            cbc_rows(z["KAT_AES.zip"], z["aesmmt.zip"], z["aesmct.zip"]))
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids)), "duplicate ids"
    sub = subset(rows)
    out = {FULL: gz(tsv(rows)), SUBSET: tsv(sub), MANIFEST: manifest(sub)}
    counts = {}
    for r in rows:
        counts[r["family"]] = counts.get(r["family"], 0) + 1
    print(f"{len(rows)} vectors {counts}; {len(sub)} shipped")

    if a.check:
        bad = []
        for path, data in out.items():
            if not os.path.exists(path) or open(path, "rb").read() != data:
                bad.append(os.path.relpath(path, ROOT))
        if bad:
            sys.exit("differs: " + ", ".join(bad))
        print("make-cavp --check: every file matches")
        return
    os.makedirs(os.path.dirname(FULL), exist_ok=True)
    for path, data in out.items():
        with open(path, "wb") as f:
            f.write(data)
        print("wrote", os.path.relpath(path, ROOT), len(data), "bytes")


if __name__ == "__main__":
    main()
