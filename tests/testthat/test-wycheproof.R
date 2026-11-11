test_that("every Wycheproof case gets the answer its result demands (#70)", {
  # Project Wycheproof's vectors probe known attacks and edge cases: a
  # "valid" case must be accepted with the right output, an "invalid" one
  # refused, and an "acceptable" one may go either way but, if accepted,
  # must give the right output. Refusing means a zucrypt condition; any
  # other error fails here. AES-GCM, HMAC-SHA-1/2, ECDSA on P-256/384/521,
  # RSA PKCS#1 v1.5 and PSS verification, RSA OAEP and PKCS#1 v1.5
  # decryption, ECDH on P-256/384/521 with SubjectPublicKeyInfo peers, and
  # X25519 (tools/make-wycheproof.py).
  v <- wycheproof_vectors()
  if (wycheproof_full()) expect_identical(nrow(v), WYCHEPROOF_FULL_COUNT)
  expect_setequal(unique(v$family),
                  c("gcm", "hmac", "ecdsa", "rsa-pkcs1-sig", "rsa-pss",
                    "rsa-oaep", "rsa-pkcs1-crypt", "ecdh", "x25519"))
  keys <- new.env()
  wrong <- character(0)
  for (i in seq_len(nrow(v))) {
    r <- v[i, ]
    got <- wycheproof_case(r, keys)
    bad <- switch(
      r$result,
      valid = !got$accepted || !isTRUE(got$right),
      invalid = got$accepted,
      acceptable = got$accepted && !isTRUE(got$right),
      TRUE
    )
    if (bad) {
      wrong <- c(wrong, sprintf("%s #%s (%s; %s): %s", r$file, r$tc_id,
                                r$result, r$flags,
                                if (got$accepted) "accepted" else "refused"))
    }
  }
  expect_identical(wrong, character(0))
  expect_gt(nrow(v), 100L)
})
