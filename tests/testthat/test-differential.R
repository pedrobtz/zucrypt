test_that("hashes and HMACs agree with openssl at random lengths and splits (#68)", {
  skip_if_not_installed("openssl")
  seed <- diff_seed()
  n <- diff_n(40L)
  blocks <- c(sha1 = 64L, sha256 = 64L, sha384 = 128L, sha512 = 128L)
  with_diff_seed(seed, for (i in seq_len(n)) {
    alg <- sample(names(blocks), 1L)
    block <- blocks[[alg]]
    data <- diff_bytes(diff_length(block))
    # Keys of every length class: empty, shorter than, exactly and longer
    # than the block (a longer one is hashed first, RFC 2104 section 2).
    key <- diff_bytes(sample(c(0L, sample.int(block - 1L, 1L), block,
                               block + sample.int(block, 1L)), 1L))
    theirs_fn <- getExportedValue("openssl", alg)
    where <- diff_where(seed, i, sprintf("%s, %d bytes, %d-byte key", alg,
                                         length(data), length(key)))
    h <- as.vector(theirs_fn(data))
    m <- as.vector(theirs_fn(data, key = key))
    splits <- diff_splits(length(data))
    expect_identical(crypt_hash(data, alg), h, info = where)
    expect_identical(native_hash(alg, data, splits), h, info = where)
    expect_identical(crypt_hmac(data, key, alg), m, info = where)
    expect_identical(native_hmac(alg, key, data, splits), m, info = where)
    # Connection input (#11), every fourth case: in memory and from a file.
    if (i %% 4L == 0L) {
      # rawConnection() returns an open connection, which crypt_hash()
      # leaves to its caller; a file(), opened by crypt_hmac(), it closes.
      con <- rawConnection(data)
      expect_identical(crypt_hash(con, alg), h, info = where)
      close(con)
      path <- tempfile()
      writeBin(data, path)
      expect_identical(crypt_hmac(file(path), key, alg), m, info = where)
      unlink(path)
    }
  })
})

test_that("AES-CBC and AES-GCM agree with openssl at random lengths (#68)", {
  skip_if_not_installed("openssl")
  seed <- diff_seed() + 1L
  n <- diff_n(40L)
  with_diff_seed(seed, for (i in seq_len(n)) {
    key <- diff_bytes(sample(c(16L, 24L, 32L), 1L))
    # CBC: openssl pads with PKCS#7, so its ciphertext is ours of the data
    # with a full block of 16s appended.
    data <- diff_bytes(16L * (diff_length(16L, 4000L) %/% 16L))
    iv <- diff_bytes(16L)
    where <- diff_where(seed, i, sprintf("AES-%d, %d bytes", 8L * length(key),
                                         length(data)))
    theirs <- as.vector(openssl::aes_cbc_encrypt(data, key, iv))
    padded <- c(data, as.raw(rep(16L, 16L)))
    expect_identical(crypt_aes_cbc_encrypt_nopad(padded, key, iv), theirs,
                     info = where)
    expect_identical(crypt_aes_cbc_decrypt_nopad(theirs, key, iv), padded,
                     info = where)
    expect_identical(native_aes("cbc", TRUE, key, iv, padded,
                                16L * diff_splits(length(padded) %/% 16L)),
                     theirs, info = where)
    # GCM: openssl returns the ciphertext without the tag; the ciphertext
    # must match, and ours must decrypt with its own tag.
    data <- diff_bytes(diff_length(16L, 4000L))
    nonce <- diff_bytes(12L)
    aad <- if (i %% 2L == 0L) diff_bytes(sample(0:40, 1L)) else NULL
    ours <- crypt_aes_gcm_encrypt(data, key, nonce, aad = aad)
    if (is.null(aad)) {
      expect_identical(as.vector(ours),
                       as.vector(openssl::aes_gcm_encrypt(data, key, nonce)),
                       info = where)
    }
    expect_identical(crypt_aes_gcm_decrypt(ours, key, aad = aad), data,
                     info = where)
  })
})

test_that("signatures, encryption and key agreement interoperate with openssl (#68)", {
  skip_if_not_installed("openssl")
  seed <- diff_seed() + 2L
  n <- max(3L, diff_n(40L) %/% 8L)
  rsa <- rsa_fixture_key("rfc7515-a2")
  ec <- list(`P-256` = ec_fixture_key("rfc6979-p256"),
             `P-384` = ec_fixture_key("rfc6979-p384"),
             `P-521` = ec_fixture_key("rfc6979-p521"))
  their <- function(k) openssl::read_key(crypt_write_pem(k))
  digests <- c("sha1", "sha256", "sha384", "sha512")
  # Some system OpenSSL builds refuse SHA-1 signatures by policy (the
  # gcc-asan container's does: "invalid digest"). That is openssl's host,
  # not zucrypt, so SHA-1 is compared only where openssl will sign with it.
  sha1_ok <- tryCatch({
    for (k in c(list(rsa), ec)) {
      tk <- their(k)
      s <- openssl::signature_create(raw(1), openssl::sha1, tk)
      stopifnot(openssl::signature_verify(raw(1), s, openssl::sha1, tk$pubkey))
    }
    TRUE
  }, error = function(e) FALSE)
  if (!sha1_ok) digests <- setdiff(digests, "sha1")
  with_diff_seed(seed, for (i in seq_len(n)) {
    msg <- diff_bytes(diff_length(64L, 3000L))
    alg <- sample(digests, 1L)
    ours_h <- hash_fun(alg)
    theirs_h <- getExportedValue("openssl", alg)
    curve <- sample(names(ec), 1L)
    where <- diff_where(seed, i, sprintf("%d-byte message, %s, %s",
                                         length(msg), alg, curve))
    for (k in list(rsa, ec[[curve]])) {
      tk <- their(k)
      sig <- crypt_signature_create(msg, ours_h, k)
      expect_true(openssl::signature_verify(msg, sig, theirs_h, tk$pubkey),
                  info = where)
      other <- openssl::signature_create(msg, theirs_h, tk)
      expect_true(crypt_signature_verify(msg, other, ours_h, k$pubkey),
                  info = where)
    }
    # RSA encryption both ways, a random message within PKCS#1 v1.5's room.
    secret <- diff_bytes(sample.int(200L, 1L))
    tk <- their(rsa)
    oaep <- i %% 2L == 0L
    expect_identical(
      openssl::rsa_decrypt(crypt_rsa_encrypt(secret, rsa$pubkey, oaep = oaep),
                           tk, oaep = oaep),
      secret, info = where
    )
    expect_identical(
      crypt_rsa_decrypt(openssl::rsa_encrypt(secret, tk$pubkey, oaep = oaep),
                        rsa, oaep = oaep),
      secret, info = where
    )
    # Agreement with a fresh peer from openssl.
    peer <- openssl::ec_keygen(curve)
    expect_identical(
      crypt_ec_dh(ec[[curve]], crypt_read_pubkey(openssl::write_pem(peer$pubkey))),
      openssl::ec_dh(their(ec[[curve]]), peer$pubkey),
      info = where
    )
    xa <- crypt_x25519_keygen()
    xb <- openssl::x25519_keygen()
    expect_identical(
      crypt_x25519_diffie_hellman(
        xa, crypt_read_x25519_pubkey(as.vector(xb$pubkey$data))
      ),
      as.vector(openssl::x25519_diffie_hellman(
        openssl::read_key(crypt_write_pem(xa)), xb$pubkey
      )),
      info = where
    )
  })
})

test_that("every key the fuzz corpus gets past the reader, openssl reads the same (#68)", {
  # One-way, on purpose: zucrypt reads more strictly than openssl (it
  # refuses keys outside the RSA size rule, other curves, trailing bytes),
  # so a refusal proves nothing. But a key zucrypt accepts from these
  # malformed and hostile inputs must be one openssl reads too, and both
  # must write it back as the same DER, private and public halves alike.
  # The corpus (fuzz/corpus/pkey, a flag byte then the input) is not in the
  # tarball, so this runs from a checkout only.
  skip_if_not_installed("openssl")
  dir <- test_path("..", "..", "fuzz", "corpus", "pkey")
  skip_if(!dir.exists(dir), "the fuzz corpus is not here (not a checkout)")
  accepted <- 0L
  for (f in list.files(dir, full.names = TRUE)) {
    bytes <- readBin(f, "raw", file.size(f))
    if (length(bytes) < 2L) next
    private <- bitwAnd(as.integer(bytes[1]), 1L) == 1L
    input <- bytes[-1]
    pem <- length(input) >= 5L && identical(rawToChar(input[1:5]), "-----")
    ours <- tryCatch(
      if (private) crypt_read_key(input) else crypt_read_pubkey(input),
      zucrypt_error = function(e) NULL
    )
    if (is.null(ours)) next
    accepted <- accepted + 1L
    what <- basename(f)
    x <- if (pem) rawToChar(input) else input
    read_theirs <- function(x, der) tryCatch(
      if (private) openssl::read_key(x, der = der)
      else openssl::read_pubkey(x, der = der),
      error = function(e) e
    )
    theirs <- read_theirs(x, !pem)
    if (inherits(theirs, "error") && !pem) {
      # openssl reads PKCS#1 DER only inside PEM (tools/make-rsa-limit-kat.R
      # does the same): wrap it in the PKCS#1 label and ask again.
      label <- if (private) "RSA PRIVATE KEY" else "RSA PUBLIC KEY"
      wrapped <- sprintf("-----BEGIN %s-----\n%s\n-----END %s-----\n", label,
                         trimws(openssl::base64_encode(input, linebreaks = TRUE)),
                         label)
      theirs <- read_theirs(wrapped, FALSE)
    }
    expect_false(inherits(theirs, "error"), info = paste(what, "openssl refused"))
    if (inherits(theirs, "error")) next
    expect_identical(crypt_write_der(ours), as.vector(openssl::write_der(theirs)),
                     info = what)
    if (private) {
      expect_identical(crypt_write_der(ours$pubkey),
                       as.vector(openssl::write_der(theirs$pubkey)), info = what)
    }
  }
  expect_gt(accepted, 50L)
})
