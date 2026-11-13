/* Just enough of <string.h> for libzstd's decompressor, which is built without a libc (the
 * runner links none): the compiler's builtins, and compiler-rt's memcpy and friends for the
 * calls it cannot expand in place. */
#ifndef RUNNER_SHIM_STRING_H
#define RUNNER_SHIM_STRING_H
#include <stddef.h>
void *memcpy(void *, const void *, size_t);
void *memmove(void *, const void *, size_t);
void *memset(void *, int, size_t);
int memcmp(const void *, const void *, size_t);
size_t strlen(const char *);
#endif
