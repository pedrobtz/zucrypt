test_that("unloading the DLL with live objects finalizes them first (#144)", {
  # pkgload::unload() and devtools::load_all() unload the namespace and then
  # the DLL. A key or context alive at that moment holds a finalizer that
  # points into zucrypt.so; on glibc dlclose() unmaps it, and the next gc()
  # that collected one jumped into unmapped memory (segfault, reproduced on
  # Linux and macOS). .onUnload() now runs every pending finalizer while
  # the code is still mapped: each object's pointer is cleared, and the
  # collection afterwards calls nothing.
  skip_if_not_installed_layout()
  lib <- dirname(system.file(package = "zucrypt"))
  res <- run_in_fresh_r(c(
    sprintf(".libPaths(c(%s, .libPaths()))", deparse(lib)),
    "library(zucrypt)",
    "keys <- replicate(20, crypt_ec_keygen('P-256'), simplify = FALSE)",
    "rsa <- crypt_rsa_keygen(1024)",
    "path <- system.file(package = 'zucrypt')",
    "unloadNamespace('zucrypt')",
    "if ('zucrypt' %in% names(getLoadedDLLs()))",
    "  library.dynam.unload('zucrypt', path)",
    "cat('DLL unloaded:', !'zucrypt' %in% names(getLoadedDLLs()), '\\n')",
    "cleared <- vapply(c(keys, list(rsa)), function(k) {",
    "  capture.output(print.default(k))[1] %in%",
    "    c('<pointer: 0x0>', '<pointer: (nil)>')",
    "}, logical(1))",
    "cat('cleared', sum(cleared), 'of', length(cleared), '\\n')",
    "rm(keys, rsa)",
    "invisible(gc())",
    "cat('survived\\n')"
  ))
  out <- paste(res$output, collapse = "\n")
  expect_identical(res$status, 0L, info = out)
  expect_match(out, "DLL unloaded: TRUE", fixed = TRUE)
  expect_match(out, "cleared 21 of 21", fixed = TRUE)
  expect_match(out, "survived", fixed = TRUE)
})
