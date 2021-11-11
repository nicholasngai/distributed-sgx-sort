#ifndef __DISTRIBUTED_SGX_SORT_COMMON_OCALLS_H
#define __DISTRIBUTED_SGX_SORT_COMMON_OCALLS_H

typedef struct ocall_mpi_status {
    int count;
    int source;
    int tag;
} ocall_mpi_status_t;

#endif /* distributed-sgx-sort/common/ocalls.h */
