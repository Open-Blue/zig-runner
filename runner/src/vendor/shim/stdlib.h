/* Just enough of <stdlib.h> for libzstd's decompressor, built without a libc (the runner links
 * none): its allocations go to the runner's allocator (`libzstd.zig` exports these). The
 * compiler's own intrinsics headers include this file too. */
#ifndef RUNNER_SHIM_STDLIB_H
#define RUNNER_SHIM_STDLIB_H
#include <stddef.h>
void *runner_zstd_malloc(size_t);
void *runner_zstd_calloc(size_t, size_t);
void runner_zstd_free(void *);
#define malloc runner_zstd_malloc
#define calloc runner_zstd_calloc
#define free runner_zstd_free
#endif
