#include "enclave/util.h"
#include <stdio.h>
#include <string.h>
#include "enclave/parallel_t.h"

int printf(const char *format, ...) {
    va_list args;
    va_start(args, format);

    char buf[256];
    vsnprintf(buf, sizeof(buf), format, args);
    ocall_puts(1, buf);
    return strnlen(buf, sizeof(buf) - 1);
}
