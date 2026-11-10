/* A driver that feeds files to a harness without libFuzzer (#94).
 *
 * libFuzzer needs clang. This needs nothing, so the same harnesses, with
 * the same oracles, replay the committed corpus on every platform CI has,
 * Rtools on Windows included: a finding on one platform becomes a regress-*
 * seed, and this is what stops it coming back on any of them.
 *
 *   ./replay_pkey FILE...     exit 0 when every input passes
 */
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size);

int main(int argc, char **argv)
{
    int i;

    for (i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        unsigned char *buf;
        long n;

        if (f == NULL || fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) < 0 ||
            fseek(f, 0, SEEK_SET) != 0) {
            fprintf(stderr, "cannot read %s\n", argv[i]);
            return 2;
        }
        buf = malloc(n > 0 ? (size_t) n : 1);
        if (buf == NULL || (n > 0 && fread(buf, 1, (size_t) n, f) != (size_t) n)) {
            fprintf(stderr, "cannot read %s\n", argv[i]);
            return 2;
        }
        fclose(f);
        (void) LLVMFuzzerTestOneInput(buf, (size_t) n);
        free(buf);
    }
    printf("replayed %d input(s); every oracle held\n", argc - 1);
    return argc > 1 ? 0 : 2;
}
