#!/usr/bin/env Rscript

## Generates tests/testthat/fixtures/kat.tsv, the known-answer vectors the
## test suite runs against, plus the MANIFEST.tsv recording where each one
## came from.
##
##   Rscript tools/make-kat.R            write the fixtures
##   Rscript tools/make-kat.R --check    regenerate and compare, changing nothing
##
## Maintainer tooling. Nothing is generated at test time: the fixtures are
## committed, and the suite reads them offline.
##
## The vectors below are published values, transcribed from the documents
## named in the `source` column. Transcription is exactly where this can go
## wrong, so --check does not merely diff the file: where the `openssl`
## package is installed it recomputes every vector with a completely
## independent implementation and compares. That is the design's requirement
## that compatibility be shown against another implementation, not against
## ourselves -- a self round trip would pass just as happily with a wrong
## constant on both sides.

FIXTURES <- file.path("tests", "testthat", "fixtures")

## --- the vectors ----------------------------------------------------------

## FIPS 180-2 / RFC 3174 / RFC 6234 sample messages.
MSG_ABC <- "abc"
MSG_448 <- "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
MSG_896 <- paste0("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn",
                  "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")

## "One million repetitions of 'a'", FIPS 180-2 A.3 / B.3 / C.3 (and the
## SHA-384 value from the same test in RFC 6234). Written in the fixture's
## repeat notation -- a byte, then how many times -- because two megabytes of
## hex is not a reviewable fixture. unhex() below and in helper-kat.R expand
## it. These are the only published vectors here that are longer than one
## compression block, so without them every multi-block result was checked
## only against this package itself (#34).
MILLION_A <- "61*1000000"

hash_vectors <- function() {
  rbind(
    data.frame(family = "hash", algorithm = "sha1", key = "", iv = "",
               input = "", output = "da39a3ee5e6b4b0d3255bfef95601890afd80709",
               source = "FIPS 180-2 / RFC 3174, empty message"),
    data.frame(family = "hash", algorithm = "sha1", key = "", iv = "",
               input = hex(MSG_ABC),
               output = "a9993e364706816aba3e25717850c26c9cd0d89d",
               source = "FIPS 180-2 A.1"),
    data.frame(family = "hash", algorithm = "sha1", key = "", iv = "",
               input = hex(MSG_448),
               output = "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
               source = "FIPS 180-2 A.2"),

    data.frame(family = "hash", algorithm = "sha256", key = "", iv = "",
               input = "",
               output = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
               source = "FIPS 180-2, empty message"),
    data.frame(family = "hash", algorithm = "sha256", key = "", iv = "",
               input = hex(MSG_ABC),
               output = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
               source = "FIPS 180-2 B.1"),
    data.frame(family = "hash", algorithm = "sha256", key = "", iv = "",
               input = hex(MSG_448),
               output = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
               source = "FIPS 180-2 B.2"),

    data.frame(family = "hash", algorithm = "sha384", key = "", iv = "",
               input = "",
               output = paste0("38b060a751ac96384cd9327eb1b1e36a21fdb71114be0743",
                               "4c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b"),
               source = "FIPS 180-2, empty message"),
    data.frame(family = "hash", algorithm = "sha384", key = "", iv = "",
               input = hex(MSG_ABC),
               output = paste0("cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163",
                               "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"),
               source = "FIPS 180-2 D.1"),

    data.frame(family = "hash", algorithm = "sha512", key = "", iv = "",
               input = "",
               output = paste0("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc",
                               "83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f",
                               "63b931bd47417a81a538327af927da3e"),
               source = "FIPS 180-2, empty message"),
    data.frame(family = "hash", algorithm = "sha512", key = "", iv = "",
               input = hex(MSG_ABC),
               output = paste0("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea2",
                               "0a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd",
                               "454d4423643ce80e2a9ac94fa54ca49f"),
               source = "FIPS 180-2 C.1"),

    ## Appended, not interleaved, so that the ids above keep their numbers.
    data.frame(family = "hash", algorithm = "sha1", key = "", iv = "",
               input = MILLION_A,
               output = "34aa973cd4c4daa4f61eeb2bdbad27316534016f",
               source = "FIPS 180-2 A.3 (one million 'a')"),
    data.frame(family = "hash", algorithm = "sha256", key = "", iv = "",
               input = MILLION_A,
               output = "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
               source = "FIPS 180-2 B.3 (one million 'a')"),
    data.frame(family = "hash", algorithm = "sha384", key = "", iv = "",
               input = hex(MSG_896),
               output = paste0("09330c33f71147e83d192fc782cd1b4753111b173b3b05d2",
                               "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"),
               source = "FIPS 180-2 D.2"),
    data.frame(family = "hash", algorithm = "sha384", key = "", iv = "",
               input = MILLION_A,
               output = paste0("9d0e1809716474cb086e834e310a4a1ced149e9c00f24852",
                               "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"),
               source = "RFC 6234 SHA-384 test 3 (one million 'a')"),
    data.frame(family = "hash", algorithm = "sha512", key = "", iv = "",
               input = hex(MSG_896),
               output = paste0("8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa1",
                               "7299aeadb6889018501d289e4900f7e4331b99dec4b5433a",
                               "c7d329eeb6dd26545e96e55b874be909"),
               source = "FIPS 180-2 C.2"),
    data.frame(family = "hash", algorithm = "sha512", key = "", iv = "",
               input = MILLION_A,
               output = paste0("e718483d0ce769644e2e42c7bc15b4638e1f98b13b204428",
                               "5632a803afa973ebde0ff244877ea60a4cb0432ce577c31b",
                               "eb009c5c2c49aa2e4eadb217ad8cc09b"),
               source = "FIPS 180-2 C.3 (one million 'a')")
  )
}

hmac_vectors <- function() {
  k1 <- strrep("0b", 20)
  jefe <- hex("Jefe")
  hi <- hex("Hi There")
  what <- hex("what do ya want for nothing?")

  rbind(
    ## RFC 2202 test cases 1 and 2 (HMAC-SHA-1).
    data.frame(family = "hmac", algorithm = "sha1", key = k1, iv = "",
               input = hi, output = "b617318655057264e28bc0b6fb378c8ef146be00",
               source = "RFC 2202 test case 1"),
    data.frame(family = "hmac", algorithm = "sha1", key = jefe, iv = "",
               input = what, output = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
               source = "RFC 2202 test case 2"),

    ## RFC 4231 test cases 1 and 2.
    data.frame(family = "hmac", algorithm = "sha256", key = k1, iv = "",
               input = hi,
               output = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
               source = "RFC 4231 test case 1"),
    data.frame(family = "hmac", algorithm = "sha384", key = k1, iv = "",
               input = hi,
               output = paste0("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec6",
                               "82aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"),
               source = "RFC 4231 test case 1"),
    data.frame(family = "hmac", algorithm = "sha512", key = k1, iv = "",
               input = hi,
               output = paste0("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec278",
                               "7ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4",
                               "be9d914eeb61f1702e696c203a126854"),
               source = "RFC 4231 test case 1"),
    data.frame(family = "hmac", algorithm = "sha256", key = jefe, iv = "",
               input = what,
               output = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
               source = "RFC 4231 test case 2"),
    data.frame(family = "hmac", algorithm = "sha512", key = jefe, iv = "",
               input = what,
               output = paste0("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd6",
                               "10270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fd",
                               "caeab1a34d4a6b4b636e070a38bce737"),
               source = "RFC 4231 test case 2"),

    ## Keys longer than the hash block, which HMAC must hash before use.
    ## Until these, that path had no independent check at all (#34).
    ## RFC 2202 cases 6 and 7 (80-byte key, SHA-1's block is 64).
    data.frame(family = "hmac", algorithm = "sha1", key = "aa*80", iv = "",
               input = hex("Test Using Larger Than Block-Size Key - Hash Key First"),
               output = "aa4ae5e15272d00e95705637ce8a3b55ed402112",
               source = "RFC 2202 test case 6"),
    data.frame(family = "hmac", algorithm = "sha1", key = "aa*80", iv = "",
               input = hex(paste0("Test Using Larger Than Block-Size Key and ",
                                  "Larger Than One Block-Size Data")),
               output = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
               source = "RFC 2202 test case 7"),
    ## RFC 4231 cases 6 and 7 (131-byte key, longer than every block here).
    data.frame(family = "hmac", algorithm = "sha256", key = "aa*131", iv = "",
               input = hex(RFC4231_6),
               output = "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
               source = "RFC 4231 test case 6"),
    data.frame(family = "hmac", algorithm = "sha384", key = "aa*131", iv = "",
               input = hex(RFC4231_6),
               output = paste0("4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f",
                               "3cd11f05033ac4c60c2ef6ab4030fe8296248df163f44952"),
               source = "RFC 4231 test case 6"),
    data.frame(family = "hmac", algorithm = "sha512", key = "aa*131", iv = "",
               input = hex(RFC4231_6),
               output = paste0("80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1",
                               "121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e52",
                               "95e64f73f63f0aec8b915a985d786598"),
               source = "RFC 4231 test case 6"),
    data.frame(family = "hmac", algorithm = "sha256", key = "aa*131", iv = "",
               input = hex(RFC4231_7),
               output = "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
               source = "RFC 4231 test case 7"),
    data.frame(family = "hmac", algorithm = "sha384", key = "aa*131", iv = "",
               input = hex(RFC4231_7),
               output = paste0("6617178e941f020d351e2f254e8fd32c602420feb0b8fb9a",
                               "dccebb82461e99c5a678cc31e799176d3860e6110c46523e"),
               source = "RFC 4231 test case 7"),
    data.frame(family = "hmac", algorithm = "sha512", key = "aa*131", iv = "",
               input = hex(RFC4231_7),
               output = paste0("e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5",
                               "a32d20cdc944b6022cac3c4982b10d5eeb55c3e4de15134676fb",
                               "6de0446065c97440fa8c6a58"),
               source = "RFC 4231 test case 7")
  )
}

RFC4231_6 <- "Test Using Larger Than Block-Size Key - Hash Key First"
RFC4231_7 <- paste0("This is a test using a larger than block-size key and a ",
                    "larger than block-size data. The key needs to be hashed ",
                    "before being used by the HMAC algorithm.")

## NIST SP 800-38A appendix F. The same four plaintext blocks throughout.
## Only the CBC vectors: ECB left in design revision 3 (#29), and its three
## F.1 vectors with it.
PT <- paste0("6bc1bee22e409f96e93d7e117393172a",
             "ae2d8a571e03ac9c9eb76fac45af8e51",
             "30c81c46a35ce411e5fbc1191a0a52ef",
             "f69f2445df4f9b17ad2b417be66c3710")
IV <- "000102030405060708090a0b0c0d0e0f"
K128 <- "2b7e151628aed2a6abf7158809cf4f3c"
K192 <- "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b"
K256 <- "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"

aes_vectors <- function() {
  rbind(
    data.frame(family = "aes-cbc", algorithm = "aes128", key = K128, iv = IV,
               input = PT,
               output = paste0("7649abac8119b246cee98e9b12e9197d",
                               "5086cb9b507219ee95db113a917678b2",
                               "73bed6b8e3c1743b7116e69e22229516",
                               "3ff1caa1681fac09120eca307586e1a7"),
               source = "NIST SP 800-38A F.2.1 (CBC-AES128.Encrypt)"),
    data.frame(family = "aes-cbc", algorithm = "aes192", key = K192, iv = IV,
               input = PT,
               output = paste0("4f021db243bc633d7178183a9fa071e8",
                               "b4d9ada9ad7dedf4e5e738763f69145a",
                               "571b242012fb7ae07fa9baac3df102e0",
                               "08b0e27988598881d920a9e64f5615cd"),
               source = "NIST SP 800-38A F.2.3 (CBC-AES192.Encrypt)"),
    data.frame(family = "aes-cbc", algorithm = "aes256", key = K256, iv = IV,
               input = PT,
               output = paste0("f58c4c04d6e5f1ba779eabfb5f7bfbd6",
                               "9cfc4e967edb808d679f777bc6702c7d",
                               "39f23369a9d9bacfa530e26304231461",
                               "b2eb05e2c39be9fcda6c19078c6a9d1b"),
               source = "NIST SP 800-38A F.2.5 (CBC-AES256.Encrypt)")
  )
}

## AES-GCM: the test cases of McGrew and Viega, "The Galois/Counter Mode of
## Operation (GCM)", revised 2005, appendix B, which NIST SP 800-38D cites --
## every case with a 96-bit IV, the only length this package accepts. `tag`
## is the full 128-bit tag. openssl's R GCM returns no tag and takes no
## associated data, so cross_check() compares only the ciphertext of the
## cases without it; tools/check-kat.py checks every tag against Python's
## `cryptography`.
GCM_K <- "feffe9928665731c6d6a8f9467308308"
GCM_IV <- "cafebabefacedbaddecaf888"
GCM_P <- paste0("d9313225f88406e5a55909c5aff5269a",
                "86a7a9531534f7da2e4c303d8a318a72",
                "1c3c0c95956809532fcf0e2449a6b525",
                "b16aedf5aa0de657ba637b391aafd255")
GCM_P60 <- substr(GCM_P, 1, 120)
GCM_A <- "feedfacedeadbeeffeedfacedeadbeefabaddad2"

aead_vectors <- function() {
  z12 <- strrep("00", 12)
  row <- function(algorithm, key, iv, aad, input, output, tag, case) {
    data.frame(family = "aead", algorithm = algorithm, key = key, iv = iv,
               aad = aad, input = input, output = output, tag = tag,
               source = sprintf("GCM specification (McGrew-Viega), test case %d",
                                case))
  }
  rbind(
    row("aes-gcm", strrep("00", 16), z12, "", "", "",
        "58e2fccefa7e3061367f1d57a4e7455a", 1),
    row("aes-gcm", strrep("00", 16), z12, "", strrep("00", 16),
        "0388dace60b6a392f328c2b971b2fe78",
        "ab6e47d42cec13bdf53a67b21257bddf", 2),
    row("aes-gcm", GCM_K, GCM_IV, "", GCM_P,
        paste0("42831ec2217774244b7221b784d0d49c",
               "e3aa212f2c02a4e035c17e2329aca12e",
               "21d514b25466931c7d8f6a5aac84aa05",
               "1ba30b396a0aac973d58e091473f5985"),
        "4d5c2af327cd64a62cf35abd2ba6fab4", 3),
    row("aes-gcm", GCM_K, GCM_IV, GCM_A, GCM_P60,
        paste0("42831ec2217774244b7221b784d0d49c",
               "e3aa212f2c02a4e035c17e2329aca12e",
               "21d514b25466931c7d8f6a5aac84aa05",
               "1ba30b396a0aac973d58e091"),
        "5bc94fbc3221a5db94fae95ae7121a47", 4),
    row("aes-gcm", strrep("00", 24), z12, "", "", "",
        "cd33b28ac773f74ba00ed1f312572435", 7),
    row("aes-gcm", strrep("00", 24), z12, "", strrep("00", 16),
        "98e7247c07f0fe411c267e4384b0f600",
        "2ff58d80033927ab8ef4d4587514f0fb", 8),
    row("aes-gcm", strrep("00", 32), z12, "", "", "",
        "530f8afbc74536b9a963b4f1c4cb738b", 13),
    row("aes-gcm", strrep("00", 32), z12, "", strrep("00", 16),
        "cea7403d4d606b6e074ec5d3baf39d18",
        "d0d1c8a799996bf0265b98b5d48ab919", 14),
    row("aes-gcm", paste0(GCM_K, GCM_K), GCM_IV, "", GCM_P,
        paste0("522dc1f099567d07f47f37a32a84427d",
               "643a8cdcbfe5c0c97598a2bd2555d1aa",
               "8cb08e48590dbb3da7b08b1056828838",
               "c5f61e6393ba7a0abcc9f662898015ad"),
        "b094dac5d93471bdec1a502270e3cc6c", 15),
    row("aes-gcm", paste0(GCM_K, GCM_K), GCM_IV, GCM_A, GCM_P60,
        paste0("522dc1f099567d07f47f37a32a84427d",
               "643a8cdcbfe5c0c97598a2bd2555d1aa",
               "8cb08e48590dbb3da7b08b1056828838",
               "c5f61e6393ba7a0abcc9f662"),
        "76fc6ece0f4e1768cddf8853bb2d551b", 16)
  )
}

## PBKDF2-HMAC. SHA-1 from RFC 6070 (all but case 4, whose 16,777,216
## iterations take too long for a test suite), SHA-256 from RFC 7914
## section 11. No standard publishes SHA-384 or SHA-512 vectors; those two
## rows are computed with Python's hashlib.pbkdf2_hmac, an implementation
## that shares no code with the backend, and say so in their source.
PBKDF2_SHA384 <- paste0("559726be38db125bc85ed7895f6e3cf574c7a01c080c3447",
                        "db1e8a76764deb3c307b94853fbe424f6488c5f4f1289626")
PBKDF2_SHA512 <- paste0("d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5",
                        "143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5")

kdf_vectors <- function() {
  row <- function(algorithm, password, salt, iterations, output, source) {
    data.frame(family = "pbkdf2", algorithm = algorithm, password = password,
               salt = salt, iterations = iterations, output = output,
               source = source)
  }
  pw <- hex("password")
  salt <- hex("salt")
  rbind(
    row("sha1", pw, salt, 1, "0c60c80f961f0e71f3a9b524af6012062fe037a6",
        "RFC 6070 test case 1"),
    row("sha1", pw, salt, 2, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957",
        "RFC 6070 test case 2"),
    row("sha1", pw, salt, 4096, "4b007901b765489abead49d926f721d065a429c1",
        "RFC 6070 test case 3"),
    row("sha1", hex("passwordPASSWORDpassword"),
        hex("saltSALTsaltSALTsaltSALTsaltSALTsalt"), 4096,
        "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
        "RFC 6070 test case 5"),
    row("sha1", "7061737300776f7264", "7361006c74", 4096,
        "56fa6aa75548099dcc37d7f03425e0c3", "RFC 6070 test case 6"),
    row("sha256", hex("passwd"), salt, 1,
        paste0("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc",
               "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"),
        "RFC 7914 section 11, first PBKDF2-HMAC-SHA256 vector"),
    row("sha256", hex("Password"), hex("NaCl"), 80000,
        paste0("4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56",
               "a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d"),
        "RFC 7914 section 11, second PBKDF2-HMAC-SHA256 vector"),
    row("sha384", pw, salt, 4096, PBKDF2_SHA384,
        "Python hashlib.pbkdf2_hmac (no published vector)"),
    row("sha512", pw, salt, 4096, PBKDF2_SHA512,
        "Python hashlib.pbkdf2_hmac (no published vector)")
  )
}

## --- helpers --------------------------------------------------------------

hex <- function(x) paste(format(as.raw(utf8ToInt(x)), width = 2), collapse = "")

## Hex, or the repeat notation "HH*N": byte HH, N times. Kept identical to
## unhex() in tests/testthat/helper-kat.R.
unhex <- function(x) {
  if (!nzchar(x)) return(raw(0))
  if (grepl("^[0-9a-f]{2}\\*[0-9]+$", x)) {
    parts <- strsplit(x, "*", fixed = TRUE)[[1L]]
    return(rep(as.raw(strtoi(parts[1L], 16L)), as.integer(parts[2L])))
  }
  as.raw(strtoi(substring(x, seq(1, nchar(x), 2), seq(2, nchar(x), 2)), 16L))
}

with_ids <- function(out) {
  out$id <- sprintf("%s-%s-%02d", out$family, out$algorithm,
                    ave(seq_len(nrow(out)), out$family, out$algorithm,
                        FUN = seq_along))
  out
}

all_vectors <- function() {
  out <- with_ids(rbind(hash_vectors(), hmac_vectors(), aes_vectors()))
  out[, c("id", "family", "algorithm", "key", "iv", "input", "output", "source")]
}

## Each of these files has its own columns, so each is its own table.
AEAD_COLUMNS <- c("id", "algorithm", "key", "iv", "aad", "input", "output",
                  "tag")
KDF_COLUMNS <- c("id", "algorithm", "password", "salt", "iterations",
                 "output")

## Recompute every vector with openssl, which shares no code with the backend
## this package vendors. A wrong transcription fails here rather than looking
## like a backend bug later.
cross_check <- function(v) {
  if (!requireNamespace("openssl", quietly = TRUE)) {
    message("openssl is not installed: skipping the independent cross-check.")
    return(invisible(0L))
  }
  checked <- 0L
  skipped <- 0L
  for (i in seq_len(nrow(v))) {
    row <- v[i, ]
    input <- unhex(row$input)
    got <- switch(
      row$family,
      hash = switch(row$algorithm,
                    sha1 = openssl::sha1(input),
                    sha256 = openssl::sha256(input),
                    sha384 = openssl::sha384(input),
                    sha512 = openssl::sha512(input)),
      hmac = switch(row$algorithm,
                    sha1 = openssl::sha1(input, key = unhex(row$key)),
                    sha256 = openssl::sha256(input, key = unhex(row$key)),
                    sha384 = openssl::sha384(input, key = unhex(row$key)),
                    sha512 = openssl::sha512(input, key = unhex(row$key))),
      "aes-cbc" = openssl::aes_cbc_encrypt(input, key = unhex(row$key),
                                           iv = unhex(row$iv)),
      NULL
    )
    if (is.null(got)) {
      skipped <<- skipped + 1L
      next
    }
    if (row$family == "aes-cbc") {
      ## openssl pads; compare only the blocks the vector covers.
      got <- got[seq_len(length(input))]
    }
    got <- paste(format(as.raw(got), width = 2), collapse = "")
    if (!identical(got, row$output)) {
      stop(sprintf("cross-check FAILED for %s\n  openssl:   %s\n  fixture:   %s",
                   row$id, got, row$output), call. = FALSE)
    }
    checked <- checked + 1L
  }
  message(sprintf("cross-checked %d of %d vectors against openssl (%d skipped).",
                  checked, nrow(v), skipped))
  invisible(checked)
}

## openssl's GCM returns the ciphertext without a tag and takes no
## associated data, so only the ciphertext of the cases with no associated
## data can be compared. The tags are tools/check-kat.py's.
cross_check_aead <- function(v) {
  if (!requireNamespace("openssl", quietly = TRUE)) {
    return(invisible(0L))
  }
  checked <- 0L
  for (i in seq_len(nrow(v))) {
    row <- v[i, ]
    if (nzchar(row$aad) || !nzchar(row$input)) next
    got <- openssl::aes_gcm_encrypt(unhex(row$input), key = unhex(row$key),
                                    iv = unhex(row$iv))
    got <- paste(format(as.raw(got), width = 2), collapse = "")
    if (!identical(got, row$output)) {
      stop(sprintf("cross-check FAILED for %s\n  openssl:   %s\n  fixture:   %s",
                   row$id, got, row$output), call. = FALSE)
    }
    checked <- checked + 1L
  }
  message(sprintf(paste0("cross-checked the ciphertext of %d of %d AEAD ",
                         "vectors against openssl."), checked, nrow(v)))
  invisible(checked)
}

write_fixtures <- function(v, aead, kdf, dir) {
  dir.create(dir, recursive = TRUE, showWarnings = FALSE)
  tsv <- function(x, file) {
    utils::write.table(x, file.path(dir, file),
                       sep = "\t", quote = FALSE, row.names = FALSE)
  }
  tsv(v[, c("id", "family", "algorithm", "key", "iv", "input", "output")],
      "kat.tsv")
  tsv(aead[, AEAD_COLUMNS], "aead.tsv")
  tsv(kdf[, KDF_COLUMNS], "kdf.tsv")
  manifest <- rbind(
    data.frame(file = "kat.tsv", id = v$id, source = v$source),
    data.frame(file = "aead.tsv", id = aead$id, source = aead$source),
    data.frame(file = "kdf.tsv", id = kdf$id, source = kdf$source)
  )
  manifest$generator <- "tools/make-kat.R"
  tsv(manifest, "MANIFEST.tsv")
}

## --- main -----------------------------------------------------------------

main <- function(args) {
  check <- "--check" %in% args
  v <- all_vectors()
  aead <- with_ids(aead_vectors())
  kdf <- with_ids(kdf_vectors())
  cross_check(v)
  cross_check_aead(aead)

  if (!check) {
    write_fixtures(v, aead, kdf, FIXTURES)
    message(sprintf(paste0("wrote %s/kat.tsv (%d vectors), aead.tsv (%d), ",
                           "kdf.tsv (%d) and MANIFEST.tsv"),
                    FIXTURES, nrow(v), nrow(aead), nrow(kdf)))
    return(invisible(TRUE))
  }

  tmp <- tempfile("kat-check-")
  write_fixtures(v, aead, kdf, tmp)
  ok <- TRUE
  for (f in c("kat.tsv", "aead.tsv", "kdf.tsv", "MANIFEST.tsv")) {
    a <- file.path(FIXTURES, f)
    if (!file.exists(a)) {
      message("MISSING ", a); ok <- FALSE; next
    }
    if (!identical(readLines(a, warn = FALSE),
                   readLines(file.path(tmp, f), warn = FALSE))) {
      message("DIFFERS ", a); ok <- FALSE
    }
  }
  unlink(tmp, recursive = TRUE)
  if (!ok) {
    stop("fixtures do not match this generator; re-run without --check",
         call. = FALSE)
  }
  message("fixtures match the generator.")
  invisible(TRUE)
}

main(commandArgs(trailingOnly = TRUE))
