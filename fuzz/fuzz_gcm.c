/* Fuzz AES-GCM decryption, zuc_aead_decrypt() (#94).
 *
 * Input: a 16- or 32-byte key (by the first byte's top bit), a 12-byte
 * nonce, a byte giving the AAD's length, the AAD, a control byte, a 16-byte
 * tag, and the rest as data.
 *
 * The oracle, three ways:
 *
 * 1. The data, encrypted, decrypts to itself.
 * 2. That ciphertext with one bit changed -- in the ciphertext, the tag, the
 *    AAD or the nonce, chosen by the control byte -- or with the tag cut to
 *    another length, is ZUC_ERR_AUTH, and the output is all zeros: no
 *    unauthenticated plaintext ever reaches the caller.
 * 3. The data read as ciphertext under the input's own tag is, almost
 *    always, ZUC_ERR_AUTH with zeros. If it is accepted, the plaintext must
 *    encrypt back to exactly that ciphertext and tag.
 */
#include "fuzz_common.h"

#define MAX_DATA 4096

static uint8_t pt[MAX_DATA], ct[MAX_DATA], out[MAX_DATA + 1];

static void require_auth_fail(zuc_status st, size_t len, const char *what)
{
    REQUIRE(st == ZUC_ERR_AUTH, "%s: %s, want ZUC_ERR_AUTH", what,
            zuc_status_name(st));
    REQUIRE(fuzz_all(out, len, 0), "%s: plaintext left in the output", what);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    size_t key_len, aad_len, len, pos, k;
    uint8_t key[32], nonce[12], aad[256], tag[16], tag2[16], given[16];
    uint8_t ctl;
    zuc_status st;

    fuzz_init();
    if (size < 1) return 0;
    key_len = (data[0] & 0x80) ? 32 : 16;
    if (size < key_len + 12 + 1) return 0;
    memcpy(key, data, key_len);
    memcpy(nonce, data + key_len, 12);
    pos = key_len + 12;
    aad_len = data[pos++];
    if (size < pos + aad_len + 1 + 16) return 0;
    memcpy(aad, data + pos, aad_len);
    pos += aad_len;
    ctl = data[pos++];
    memcpy(given, data + pos, 16);
    pos += 16;
    len = size - pos;
    if (len > MAX_DATA) len = MAX_DATA;
    memcpy(pt, data + pos, len);

    /* 1. Round trip. */
    st = zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, key_len, nonce, 12,
                          aad_len ? aad : NULL, aad_len, len ? pt : NULL, len,
                          len ? ct : NULL, tag, 16);
    REQUIRE(st == ZUC_OK, "encrypt: %s", zuc_status_name(st));
    memset(out, 0xee, sizeof out);
    st = zuc_aead_decrypt(ZUC_ALG_AES_GCM, key, key_len, nonce, 12,
                          aad_len ? aad : NULL, aad_len, len ? ct : NULL, len,
                          tag, 16, len ? out : NULL);
    REQUIRE(st == ZUC_OK && memcmp(out, pt, len) == 0, "round trip: %s",
            zuc_status_name(st));
    REQUIRE(out[len] == 0xee, "wrote past the plaintext");

    /* 2. One bit changed, where the control byte says. */
    {
        int field = ctl & 3;
        uint8_t bit = (uint8_t) (1u << ((ctl >> 2) & 7));
        uint8_t *target = field == 0 ? ct : field == 1 ? tag
                        : field == 2 ? aad : nonce;
        size_t n = field == 0 ? len : field == 1 ? 16
                 : field == 2 ? aad_len : 12;
        if (n > 0) {
            k = (size_t) data[0] % n;
            target[k] ^= bit;
            memset(out, 0xee, sizeof out);
            st = zuc_aead_decrypt(ZUC_ALG_AES_GCM, key, key_len, nonce, 12,
                                  aad_len ? aad : NULL, aad_len,
                                  len ? ct : NULL, len, tag, 16,
                                  len ? out : NULL);
            require_auth_fail(st, len, "one bit changed");
            target[k] ^= bit;
        }
        /* Every other tag length. */
        for (k = 0; k <= 17; k++) {
            if (k == 16) continue;
            memset(out, 0xee, sizeof out);
            st = zuc_aead_decrypt(ZUC_ALG_AES_GCM, key, key_len, nonce, 12,
                                  aad_len ? aad : NULL, aad_len,
                                  len ? ct : NULL, len, tag, k,
                                  len ? out : NULL);
            require_auth_fail(st, len, "tag length");
        }
    }

    /* 3. The input as ciphertext, under its own tag. */
    memset(out, 0xee, sizeof out);
    st = zuc_aead_decrypt(ZUC_ALG_AES_GCM, key, key_len, nonce, 12,
                          aad_len ? aad : NULL, aad_len, len ? pt : NULL, len,
                          given, 16, len ? out : NULL);
    if (st == ZUC_OK) {
        st = zuc_aead_encrypt(ZUC_ALG_AES_GCM, key, key_len, nonce, 12,
                              aad_len ? aad : NULL, aad_len,
                              len ? out : NULL, len, len ? ct : NULL, tag2, 16);
        REQUIRE(st == ZUC_OK && memcmp(ct, pt, len) == 0 &&
                memcmp(tag2, given, 16) == 0,
                "accepted a ciphertext that does not re-encrypt to itself");
    } else {
        require_auth_fail(st, len, "arbitrary ciphertext");
    }
    REQUIRE_NO_LEAK();
    return 0;
}
