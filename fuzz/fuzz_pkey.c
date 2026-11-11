/* Fuzz the key reader, zuc_pkey_parse() (#94).
 *
 * Input: one flag byte (bit 0: read as a private key), then the bytes the
 * reader gets -- PEM or DER of any encoding it takes.
 *
 * The oracle. A refusal is a status from the documented set and leaves no
 * handle. A key it accepts is a fixed point of writing and reading: in
 * every format the key can be written in, and for the public half too, the
 * written bytes read back to a key of the same type, size and half, and
 * that key writes the same bytes again. Raw export and import agree in the
 * same way. A reader that accepted a malformed key and normalised it into
 * a different one, or a writer that emitted something its own reader
 * refuses, breaks one of these.
 */
#include "fuzz_common.h"

static const zuc_pkey_format formats[] = {
    ZUC_PKEY_PKCS1_DER, ZUC_PKEY_PKCS1_PEM, ZUC_PKEY_INFO_DER, ZUC_PKEY_INFO_PEM
};

static uint8_t buf1[ZUC_PKEY_MAX_WRITE_SIZE], buf2[ZUC_PKEY_MAX_WRITE_SIZE];

static void fixed_point(const zuc_pkey *key, zuc_pkey_format f, int pub_only)
{
    size_t n1 = 0, n2 = 0;
    zuc_pkey *again = NULL;
    int want_private = zuc_pkey_is_private(key) && !pub_only;
    zuc_status st = zuc_pkey_write(key, f, pub_only, buf1, sizeof buf1, &n1);

    if (st != ZUC_OK) {
        /* A format this key type has no form in. */
        REQUIRE(st == ZUC_ERR_UNSUPPORTED || st == ZUC_ERR_INVALID_ARGUMENT,
                "write format %d: %s", (int) f, zuc_status_name(st));
        return;
    }
    REQUIRE(n1 > 0 && n1 <= sizeof buf1, "write length %zu", n1);
    st = zuc_pkey_parse(buf1, n1, want_private, &again);
    REQUIRE(st == ZUC_OK, "own format %d (public only %d) refused: %s",
            (int) f, pub_only, zuc_status_name(st));
    REQUIRE(zuc_pkey_type(again) == zuc_pkey_type(key), "type changed");
    REQUIRE(zuc_pkey_bits(again) == zuc_pkey_bits(key), "size changed");
    REQUIRE(zuc_pkey_is_private(again) == want_private, "half changed");
    st = zuc_pkey_write(again, f, pub_only, buf2, sizeof buf2, &n2);
    REQUIRE(st == ZUC_OK && n2 == n1 && memcmp(buf1, buf2, n1) == 0,
            "format %d is not a fixed point", (int) f);
    zuc_pkey_free(again);
}

static void raw_round_trip(const zuc_pkey *key, int pub_only)
{
    size_t n1 = 0, n2 = 0;
    zuc_pkey *again = NULL;
    int want_private = zuc_pkey_is_private(key) && !pub_only;
    zuc_status st = zuc_pkey_export(key, pub_only, buf1, sizeof buf1, &n1);

    REQUIRE(st == ZUC_OK, "export: %s", zuc_status_name(st));
    st = zuc_pkey_import(zuc_pkey_type(key), want_private, buf1, n1, &again);
    REQUIRE(st == ZUC_OK, "own export refused on import: %s",
            zuc_status_name(st));
    st = zuc_pkey_export(again, pub_only, buf2, sizeof buf2, &n2);
    REQUIRE(st == ZUC_OK && n2 == n1 && memcmp(buf1, buf2, n1) == 0,
            "export is not a fixed point");
    zuc_pkey_free(again);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    zuc_pkey *key = (zuc_pkey *) 0x1;
    zuc_alg type;
    zuc_status st;
    int private_key, i;

    fuzz_init();
    if (size < 1) return 0;
    private_key = data[0] & 1;
    st = zuc_pkey_parse(data + 1, size - 1, private_key, &key);
    if (st != ZUC_OK) {
        REQUIRE(st == ZUC_ERR_INVALID_ARGUMENT || st == ZUC_ERR_UNSUPPORTED ||
                st == ZUC_ERR_MEMORY, "refusal status %s", zuc_status_name(st));
        REQUIRE(key == NULL, "a refusal left a handle");
        REQUIRE_NO_LEAK();
        return 0;
    }
    type = zuc_pkey_type(key);
    REQUIRE(type == ZUC_ALG_RSA || type == ZUC_ALG_EC_P256 ||
            type == ZUC_ALG_EC_P384 || type == ZUC_ALG_EC_P521 ||
            type == ZUC_ALG_X25519, "type %d", (int) type);
    REQUIRE(!private_key || zuc_pkey_is_private(key),
            "a private read returned a public key");
    /* The size rule (zucrypt.h, #141): 1024 to 4096 bits, whole bytes. */
    REQUIRE(type != ZUC_ALG_RSA ||
            (zuc_pkey_bits(key) >= 1024 && zuc_pkey_bits(key) <= 4096 &&
             zuc_pkey_bits(key) % 8 == 0),
            "RSA key of %zu bits", zuc_pkey_bits(key));

    for (i = 0; i < 4; i++) {
        fixed_point(key, formats[i], 1);
        if (zuc_pkey_is_private(key)) fixed_point(key, formats[i], 0);
    }
    raw_round_trip(key, 1);
    if (zuc_pkey_is_private(key)) raw_round_trip(key, 0);

    zuc_pkey_free(key);
    REQUIRE_NO_LEAK();
    return 0;
}
