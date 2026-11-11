# Helpers for test-connection.R, here because testthat's parallel and
# shuffled runs do not see a test file's file scope.

chunk <- 1048576L

write_temp <- function(bytes) {
  path <- tempfile()
  writeBin(bytes, path)
  path
}

open_connections <- function() nrow(showConnections(all = FALSE))

# A non-blocking client socket that has received `bytes` while its server
# end is still open, so a read returns them and then nothing *yet*
# (isIncomplete() is TRUE). Both ends are closed when `env` exits. (#145)
half_open_socket <- function(bytes, env = parent.frame()) {
  srv <- NULL
  for (port in sample(40000:60000, 25L)) {
    srv <- tryCatch(serverSocket(port), error = function(e) NULL)
    if (!is.null(srv)) break
  }
  if (is.null(srv)) {
    testthat::skip("no free local port")
  }
  client <- socketConnection("localhost", port, blocking = FALSE, open = "rb")
  server <- socketAccept(srv, blocking = TRUE, open = "wb")
  # Base R's on.exit() registered in the caller's frame (withr is not a
  # Suggests).
  cleanup <- function() {
    close(client)
    close(server)
    close(srv)
  }
  do.call(on.exit, list(substitute(f(), list(f = cleanup)), add = TRUE),
          envir = env)
  writeBin(bytes, server)
  flush(server)
  # Wait until the bytes have arrived, so the read is deterministic.
  for (i in 1:50) {
    if (
      isIncomplete(client) || length(socketSelect(list(client), timeout = 0.1))
    ) {
      break
    }
  }
  client
}

# Every function that reads a connection, as f(con) (#145). Signature
# functions read `data` or `sig` from it.
connection_readers <- function() {
  k <- crypt_ec_keygen("P-256")
  sig <- crypt_signature_create(as.raw(1:10), crypt_sha256, k)
  list(
    crypt_hash = function(con) crypt_hash(con),
    crypt_hmac = function(con) crypt_hmac(con, as.raw(1)),
    crypt_read_key = function(con) crypt_read_key(con),
    crypt_read_pubkey = function(con) crypt_read_pubkey(con),
    `crypt_signature_create(data)` = function(con) {
      crypt_signature_create(con, crypt_sha256, k)
    },
    `crypt_signature_verify(data)` = function(con) {
      crypt_signature_verify(con, sig, crypt_sha256, k$pubkey)
    },
    `crypt_signature_verify(sig)` = function(con) {
      crypt_signature_verify(as.raw(1:10), con, crypt_sha256, k$pubkey)
    }
  )
}
