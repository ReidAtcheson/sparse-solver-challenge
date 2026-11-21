#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Execute one stage from a small launcher. The Linux RSS high-water mark
 * includes the interval between fork and exec; forking the Python driver
 * directly would put the driver's own RSS floor in the measurements. */
int main(int argc, char **argv)
{
    if (argc < 3) return 125;
    unsigned long long cap = strtoull(argv[1], NULL, 10);
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start) < 0) return 125;
    pid_t child = fork();
    if (child < 0) return 125;
    if (!child) {
        if (cap) {
            struct rlimit limit = {(rlim_t)cap, (rlim_t)cap};
            if (setrlimit(RLIMIT_AS, &limit) < 0) {
                perror("setrlimit(RLIMIT_AS)");
                _exit(125);
            }
        }
        execv(argv[2], argv + 2);
        perror("execv benchmark stage");
        _exit(125);
    }
    int status;
    struct rusage ru;
    pid_t result;
    do { result = wait4(child, &status, 0, &ru); } while (result < 0 && errno == EINTR);
    if (result != child || clock_gettime(CLOCK_MONOTONIC, &end) < 0) return 125;
    int64_t elapsed = (int64_t)(end.tv_sec - start.tv_sec) * INT64_C(1000000000)
                    + end.tv_nsec - start.tv_nsec;
    fprintf(stderr, "MEASURE %lld %ld\n", (long long)elapsed, ru.ru_maxrss);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
