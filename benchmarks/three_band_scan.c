/* Count streamed edges from the production three-band pattern generator.
 * Run each invocation under benchmarks/measure.c for process wall time and RSS. */
#include "../three_band.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

static int count_edge(void *context, size_t row, size_t column)
{
    if (row >= column) return EINVAL;
    ++*(size_t *)context;
    return 0;
}

static int number(const char *text, uintmax_t limit, uintmax_t *value)
{
    if (*text < '0' || *text > '9') return 0;
    char *end;
    errno = 0;
    *value = strtoumax(text, &end, 10);
    return errno == 0 && *end == '\0' && *value <= limit;
}

int main(int argc, char **argv)
{
    uintmax_t n, seed;
    if (argc != 3 || !number(argv[1], SIZE_MAX / 3, &n) || n < 3 ||
        !number(argv[2], UINT64_MAX, &seed)) {
        fputs("usage: three-band-scan ROWS PATTERN_SEED\n", stderr);
        return 2;
    }
    size_t edges = 0;
    int err = tb_pattern_scan(n, seed, count_edge, &edges);
    if (err) { errno = err; perror("tb_pattern_scan"); return 1; }
    printf("rows=%" PRIuMAX " seed=%" PRIuMAX " upper_edges=%zu\n", n, seed, edges);
    return edges == 3 * n - 6 ? 0 : 1;
}
