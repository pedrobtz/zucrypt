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

/* While `on` is non-zero, getrandom() is treated as refused with ENOSYS, so
 * the source falls back to /dev/urandom (#144); off forgets the fallback.
 * Returns 0, and does nothing, on a build that does not use getrandom(). */
int zuc_int_random_enosys(int on);

/* Script the next `n` (at most ZUC_RANDOM_SCRIPT_MAX) calls to getrandom():
 * a step k > 0 is the real call asked for at most k bytes, a short read;
 * a ZUC_RANDOM_STEP_* value fails the call with that errno instead. Calls
 * after the script are the real ones. So the suite can drive the paths a
 * real kernel takes only now and then (#119). Returns the number of steps
 * the previous script left unused, or -1, doing nothing, on a build that
 * does not use getrandom(). Test harness only. */
#define ZUC_RANDOM_SCRIPT_MAX 16
#define ZUC_RANDOM_STEP_EINTR  (-1)
#define ZUC_RANDOM_STEP_EIO    (-2)
#define ZUC_RANDOM_STEP_EPERM  (-3)
#define ZUC_RANDOM_STEP_ENOSYS (-4)
int zuc_int_random_script(const int *steps, int n);

/* Make the backend's `n`th allocation from now fail (n >= 1), once; 0
 * switches it off. Only allocations through zuc_int_calloc() count -- the
 * backend's, not the adapter's own -- so a test can fail an operation at a
 * chosen point inside the backend (#108, #116). Test harness only. */
void zuc_int_alloc_fail_at(long n);

/* How many allocations are still to come before the injected failure: 0
 * once it has fired (or when none is set). A sweep that sees a non-zero
 * value after an operation knows the operation made fewer allocations than
 * the position it was asked to fail, and has been swept to its end. */
long zuc_int_alloc_fail_pending(void);

/* The residue scan (#137). While armed with `needle`, every block the
 * backend allocates through zuc_int_calloc() is remembered, and when the
 * backend frees it through zuc_int_free() it is searched for `needle`
 * first: a hit is a secret left in freed memory. Blocks allocated before
 * arming are not searched. Disarming returns the number of hits, or -1 if
 * more blocks were live at once than the scan can remember (a test that
 * sees -1 has checked nothing). `needle` must outlive the armed period; a
 * zero length arms the bookkeeping with nothing to find. Test harness only. */
void zuc_int_residue_arm(const unsigned char *needle, size_t len);
long zuc_int_residue_disarm(void);

/* The scan's positive control: a backend block freed with a needle in it
 * counts 1, and the same block wiped before it is freed counts 10. Returns
 * the sum, 1 when the scan works. */
long zuc_int_residue_control(void);

#endif /* ZUC_LIVE_H */
