#define _POSIX_C_SOURCE 200809L
#include "scratch.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

FILE *private_scratch(void)
{
    const char *dir = getenv("TMPDIR");
    FILE *stream = NULL;
    if (!dir || !*dir) {
        stream = tmpfile();
    } else {
        static const char suffix[] = "/stencil.XXXXXX";
        size_t n = strlen(dir);
        char *name = malloc(n + sizeof(suffix));
        if (!name) {
            perror("allocate scratch path");
            exit(1);
        }
        memcpy(name, dir, n);
        memcpy(name + n, suffix, sizeof(suffix));
        int fd = mkstemp(name);
        if (fd >= 0) {
            if (unlink(name) == 0)
                stream = fdopen(fd, "w+b");
            if (!stream)
                close(fd);
        }
        free(name);
    }
    if (!stream) {
        perror("create private scratch");
        exit(1);
    }
    return stream;
}
