#ifndef __DISTRIBUTED_SGX_SORT_COMMON_ERROR_H
#define __DISTRIBUTED_SGX_SORT_COMMON_ERROR_H

#define handle_mbedtls_error(errno) \
    _handle_mbedtls_error(errno, __FILE__, __LINE__)
void _handle_mbedtls_error(int errno, const char *file, int line);

#endif /* distributed-sgx-sort/common/error.h */
