/* Just enough of <stdlib.h> for the C libraries built into the runner (libzstd, zlib-ng), which
 * has no libc: their allocations go to the runner's allocator (`src/c_alloc.zig`). The compiler's
 * own intrinsics headers include this file too. */
#ifndef RUNNER_SHIM_STDLIB_H
#define RUNNER_SHIM_STDLIB_H
#include <stddef.h>
void *runner_malloc(size_t);
void *runner_calloc(size_t, size_t);
void runner_free(void *);
#define malloc runner_malloc
#define calloc runner_calloc
#define free runner_free
#define llabs(x) __builtin_llabs(x)
#endif
