#include "error.h"
#include <stdio.h>
#include <mbedtls/error.h>

void _handle_mbedtls_error(int errno, const char *file, int line) {
    char error[256];
    mbedtls_strerror(errno, error, sizeof(error));
    fprintf(stderr, "%s:%d: %s\n", file, line, error);
}
