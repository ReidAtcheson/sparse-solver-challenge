#ifndef STENCIL_SCRATCH_H
#define STENCIL_SCRATCH_H
#include <stdio.h>
/* Opens an unlinked private read/write file on TMPDIR, or the system default. */
FILE *private_scratch(void);
#endif
