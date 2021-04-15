#include "error.h"
#include <mbedtls/error.h>

void handle_mbedtls_error(int errno) {
    char error[16];
    mbedtls_strerror(errno, error, sizeof(error));
}
