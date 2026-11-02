/* zucrypt: the adapter's hooks for the test suite -- the live-context
 * count, and a switch that makes the random source fail.
 *
 * Its own header, with no backend and no R vocabulary, because both halves
 * of src/ need it: the adapter counts, and the test harness in
 * zucrypt_test.c reads -- and the harness may include neither an R-free
 * header that pulls in PSA (zuc_internal.h) nor anything the archive does
 * not contain. tools/check-layering.sh holds it to the adapter's rules.
 *
 * Not part of any ABI and not installed.
 */

#ifndef ZUC_LIVE_H
#define ZUC_LIVE_H

/* Handles created by zuc_hash_new(), zuc_hmac_new() and zuc_aes_new() and
 * not yet freed, in this copy of the library. Not atomic: the library is
 * main-thread only. A test compares it before and after an operation that
 * was interrupted or failed; any difference is a leaked context, which in
 * this package means leaked key material. The pattern is zukomp's
 * zu_int_outbuf_live_count(). */
long zuc_int_live_contexts(void);

/* While `on` is non-zero, the operating-system random source reports
 * failure without reading anything: zuc_random_bytes() returns
 * ZUC_ERR_ENTROPY and the backend's call-out returns its own entropy error.
 * Only the test harness calls it, and it always switches it back off. */
void zuc_int_random_fail(int on);

#endif /* ZUC_LIVE_H */
