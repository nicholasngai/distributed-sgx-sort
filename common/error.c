#include "error.h"
#include <stdarg.h>
#include <stdio.h>
#include <mbedtls/error.h>
#include "common/defs.h"
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include <sgx_error.h>
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

#define fprintf(...)
#define vfprintf(...)

#pragma GCC diagnostic ignored "-Wunused-parameter"

void _handle_mbedtls_error(int ret, const char *msg, const char *file,
        int line) {
    char error[256];
    mbedtls_strerror(ret, error, sizeof(error));
    fprintf(stderr, "%s:%d: %s: %s\n", file, line, msg, error);
}

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
void _handle_sgx_error(sgx_status_t result, const char *msg, const char *file,
        int line) {
    fprintf(stderr, "%s:%d: %s: %d\n", file, line, msg, result);
}
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

void _handle_error_string(const char *file, int line, const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "%s:%d: ", file, line);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
}
