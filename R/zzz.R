# Before the namespace and its DLL go -- unloadNamespace(), which
# pkgload::unload() and devtools::load_all() use -- every key and context
# still alive is finalized while its finalizer, code in zucrypt.so, is still
# mapped. After the DLL was unmapped, the next collection of such an object
# called into unmapped memory (#144). The backend is not torn down: a table
# consumer holding zucrypt_api() pointers is left pointing into unmapped
# code, which design section 8.2 makes unsupported.
.onUnload <- function(libpath) {
  .Call(zucrypt_unload_finalizers)
}
