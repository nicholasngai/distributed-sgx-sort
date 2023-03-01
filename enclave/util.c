#include "enclave/util.h"
#include <errno.h>
#include <stdio.h>
#include "enclave/parallel_t.h"

void printf(const char *format, ...) {
    va_list args;
    va_start(args, format);

    char buf[256];
    vsnprintf(buf, sizeof(buf), format, args);
    ocall_puts(1, buf);
}

void fprintf(int fileno, const char *format, ...) {
    va_list args;
    va_start(args, format);

    char buf[256];
    vsnprintf(buf, sizeof(buf), format, args);
    ocall_puts(fileno, buf);
}

void perror(const char *s) {
    fprintf(stderr, "%s: %d\n", s, errno);
}
