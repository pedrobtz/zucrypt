/* zucrypt: the live-context count, for the test suite.
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

#endif /* ZUC_LIVE_H */
