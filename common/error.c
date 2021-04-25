#include "error.h"
#include <stdarg.h>
#include <stdio.h>
#include <mbedtls/error.h>
#include <openenclave/bits/result.h>

void _handle_mbedtls_error(int errno, const char *msg, const char *file,
        int line) {
    char error[256];
    mbedtls_strerror(errno, error, sizeof(error));
    fprintf(stderr, "%s:%d: %s: %s\n", file, line, msg, error);
}

void _handle_oe_error(oe_result_t result, const char *msg, const char *file,
        int line) {
    fprintf(stderr, "%s:%d: %s: %s\n", file, line, msg, oe_result_str(result));
}

void _handle_error_string(const char *file, int line, const char *format, ...) {
    va_list args;
    va_start(args, format);
    fprintf(stderr, "%s:%d: ", file, line);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
}
