# The runner selects the expected AES (aes-paths.yaml, moved here so the
# macOS and Windows legs can run it from tools/ci/platform.sh).
# ZUCRYPT_EXPECT_AES names the path this runner must report.
flags <- zucrypt::crypt_info()$build_flags
str(flags)
if (!identical(flags$aes_implementation, Sys.getenv("ZUCRYPT_EXPECT_AES"))) {
  stop("expected ", Sys.getenv("ZUCRYPT_EXPECT_AES"), ", got ", flags$aes_implementation)
}
