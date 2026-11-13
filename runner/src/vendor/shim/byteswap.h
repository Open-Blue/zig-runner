/* <byteswap.h> for zlib-ng, from the compiler's builtins. */
#ifndef RUNNER_SHIM_BYTESWAP_H
#define RUNNER_SHIM_BYTESWAP_H
#define bswap_16(x) __builtin_bswap16(x)
#define bswap_32(x) __builtin_bswap32(x)
#define bswap_64(x) __builtin_bswap64(x)
#endif
