# Thin R wrappers over src/link.c. Nothing here touches zucrypt: see NAMESPACE
# for why that is the point rather than an omission.

# What this package's own copy of the backend reports, read from the linked
# archive by calling zuc_get_info().
linked_backend <- function() .Call(zl_backend)

archive_hash <- function(data, algorithm = "sha256") {
  .Call(zl_hash, algorithm, data)
}

archive_hmac <- function(data, key, algorithm = "sha256") {
  .Call(zl_hmac, algorithm, key, data)
}

# H_0 = hash(seed), H_n = hash(int32le(n - 1) || H_{n-1}).
archive_derive <- function(seed, spins, algorithm = "sha512") {
  .Call(zl_derive, seed, as.integer(spins), algorithm)
}

# CBC restarted from `iv` at every `segment` bytes.
archive_segments <- function(data, key, iv, segment, encrypt = FALSE) {
  .Call(zl_segments, data, key, iv, as.integer(segment), isTRUE(encrypt))
}

# The half of the lifecycle `useDynLib` does not do. R calls
# R_unload_zucryptlink() -- and so zuc_shutdown() -- only when the DLL is
# unloaded, and with useDynLib nothing unloads it unless the namespace says
# so here. Without this, unloadNamespace() left the backend initialised and
# its key store allocated (found by zuxlsx, zucrypt#43). A consumer of the
# archive copies this line with its own package name.
.onUnload <- function(libpath) {
  library.dynam.unload("zucryptlink", libpath)
}
