#ifndef DISTRIBUTED_SGX_SORT_ENCLAVE_UTIL_H
#define DISTRIBUTED_SGX_SORT_ENCLAVE_UTIL_H

#include <stdio.h>

#define stdout 1
#define stderr 2

void printf(const char *format, ...);
void fprintf(int fileno, const char *format, ...);
void perror(const char *s);

#endif /* distributed-sgx-sort/enclave/util.h */
