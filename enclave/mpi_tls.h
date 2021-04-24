#ifndef __DISTRIBUTED_SGX_SORT_ENCLAVE_MPI_TLS_H
#define __DISTRIBUTED_SGX_SORT_ENCLAVE_MPI_TLS_H

#include <stddef.h>
#include <mbedtls/entropy.h>

int mpi_tls_init(size_t world_rank, size_t world_size,
        mbedtls_entropy_context *entropy);
void mpi_tls_free(void);
int mpi_tls_send_bytes(const unsigned char *buf, size_t count, int dest,
        int tag);
int mpi_tls_recv_bytes(unsigned char *buf, size_t count, int src, int tag);

#endif /* distributed-sgx-sort/enclave/mpi_tls.h */
