#!/usr/bin/env python3
"""Generate the derivation known-answer vector for both consumer fixtures.

    python3 tools/make-derivation-kat.py ZUXLSX_CHECKOUT            write
    python3 tools/make-derivation-kat.py ZUXLSX_CHECKOUT --check    compare

Maintainer tooling, never run by a test. Needs msoffcrypto-tool 6.0.0, the
version zuxlsx's fixture was made with (pip install msoffcrypto-tool==6.0.0),
and a checkout of pedrobtz/zuxlsx for its committed fixture.

What it produces, and what it does not. tools/zucrypttest (the table) and
tools/zucryptlink (the archive) rehearse
the generic iterated hash that Office agile encryption uses --
H_0 = hash(seed), H_n = hash(int32le(n-1) || H_{n-1}) -- through one reused
incremental context. Until Stage 8 its only comparison was an R loop over
crypt_hash(), which shares the backend and so cannot catch a wrong primitive
(#34). This vector's oracle is msoffcrypto-tool, which shares no code with
this package: it is msoffcrypto's _derive_iterated_hash_from_password() for
the salt, spin count and hash algorithm read from zuxlsx's genuinely
encrypted fixture, with its known password.

It is test data, not Office support (design.md section 12). The fixture
stores input and output bytes -- the seed salt || UTF-16LE(password), the
spin count, the algorithm name, the result -- and nothing Office-specific:
no block keys, no key derivation beyond the loop, no verifier.
"""

import base64
import hashlib
import os
import sys
from importlib.metadata import version

from msoffcrypto.method.ecma376_agile import ECMA376Agile
import olefile
from xml.dom import minidom

FIXTURE = "tests/testthat/fixtures/ole2/two-sheets-encrypted.xlsx"
PASSWORD = "zuxlsx"  # zuxlsx's tests/testthat/fixtures/ole2/README.md
OUTS = ("tools/zucrypttest/tests/testthat/fixtures",
        "tools/zucryptlink/tests/testthat/fixtures")


def password_key_encryptor(path):
    ole = olefile.OleFileIO(path)
    raw = ole.openstream("EncryptionInfo").read()
    if raw[:8] != b"\x04\x00\x04\x00\x40\x00\x00\x00":
        sys.exit(f"{path}: not agile encryption")
    xml = minidom.parseString(raw[8:])
    node = xml.getElementsByTagName("p:encryptedKey")[0]
    return (
        base64.b64decode(node.getAttribute("saltValue")),
        int(node.getAttribute("spinCount")),
        node.getAttribute("hashAlgorithm"),
    )


def main(argv):
    if len(argv) < 2:
        sys.exit(__doc__)
    zuxlsx, check = argv[1], "--check" in argv[2:]
    found = version("msoffcrypto-tool")
    if found != "6.0.0":
        sys.exit(f"msoffcrypto-tool 6.0.0 required, found {found}")

    salt, spin, hash_name = password_key_encryptor(os.path.join(zuxlsx, FIXTURE))
    alg = {"SHA512": "sha512", "SHA384": "sha384", "SHA256": "sha256", "SHA1": "sha1"}[hash_name]
    seed = salt + PASSWORD.encode("utf-16-le")
    out = ECMA376Agile._derive_iterated_hash_from_password(PASSWORD, salt, hash_name, spin).digest()

    # Recomputed here too, independently of msoffcrypto's code path, as a
    # guard on the generator itself: the two must agree before anything is
    # written.
    h = hashlib.new(alg, seed).digest()
    for i in range(spin):
        h = hashlib.new(alg, i.to_bytes(4, "little") + h).digest()
    if h != out:
        sys.exit("msoffcrypto and hashlib disagree; refusing to write")

    kat = "id\talgorithm\tspin_count\tseed\toutput\n" + (
        f"agile-password-01\t{alg}\t{spin}\t{seed.hex()}\t{out.hex()}\n"
    )
    manifest = "file\tid\tsource\tgenerator\n" + (
        "derivation.tsv\tagile-password-01\t"
        "msoffcrypto-tool 6.0.0 ECMA376Agile._derive_iterated_hash_from_password(), "
        "salt/spinCount/hashAlgorithm of pedrobtz/zuxlsx "
        f"{FIXTURE} (password '{PASSWORD}')\ttools/make-derivation-kat.py\n"
    )

    # Both consumer fixtures carry the vector, one through the registered
    # table and one through the static archive, so both shapes are checked
    # against the same oracle. Written from here into both, never copied by
    # hand, so the two cannot drift.
    files = {"derivation.tsv": kat, "MANIFEST.tsv": manifest}
    if check:
        bad = [os.path.join(out, f) for out in OUTS for f, text in files.items()
               if not os.path.exists(os.path.join(out, f))
               or open(os.path.join(out, f)).read() != text]
        if bad:
            sys.exit(f"differs from the generator: {', '.join(bad)}")
        print("derivation fixtures match the generator.")
        return
    for out in OUTS:
        os.makedirs(out, exist_ok=True)
        for f, text in files.items():
            with open(os.path.join(out, f), "w") as fh:
                fh.write(text)
        print(f"wrote {out}/derivation.tsv ({alg}, spinCount {spin}) and MANIFEST.tsv")


if __name__ == "__main__":
    main(sys.argv)
