#ifndef DISTRIBUTED_SGX_SORT_COMMON_ERROR_H
#define DISTRIBUTED_SGX_SORT_COMMON_ERROR_H

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include <sgx_error.h>
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

#define handle_mbedtls_error(ret, msg) \
    _handle_mbedtls_error(ret, msg, __FILE__, __LINE__)
void _handle_mbedtls_error(int ret, const char *msg, const char *file,
        int line);

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#define handle_sgx_error(ret, msg) \
    _handle_sgx_error(ret, msg, __FILE__, __LINE__)
void _handle_sgx_error(sgx_status_t result, const char *msg, const char *file,
        int line);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

#define handle_error_string(...) \
    _handle_error_string(__FILE__, __LINE__, __VA_ARGS__)
void _handle_error_string(const char *file, int line, const char *format, ...)
    __attribute__ ((format (printf, 3, 4)));

#endif /* distributed-sgx-sort/common/error.h */
