#ifndef __DISTRIBUTED_SGX_SORT_ENCLAVE_MPI_TLS_H
#define __DISTRIBUTED_SGX_SORT_ENCLAVE_MPI_TLS_H

#include <stddef.h>
#include <mbedtls/entropy.h>
#include "common/ocalls.h"

struct mpi_tls_frag_header {
    size_t num_frags;
    unsigned char checksum[32]; // TODO Checksum not yet implemented.
};

enum mpi_tls_request_type {
    MPI_TLS_SEND,
    MPI_TLS_RECV,
};

typedef struct mpi_tls_request {
    enum mpi_tls_request_type type;
    size_t num_requests;
    ocall_mpi_request_t *mpi_requests;
    struct mpi_tls_frag_header header;

    void *buf;
    size_t count;
    int rank;
    int tag;
} mpi_tls_request_t;

int mpi_tls_init(size_t world_rank, size_t world_size,
        mbedtls_entropy_context *entropy);
void mpi_tls_free(void);
int mpi_tls_send_bytes(const void *buf, size_t count, int dest, int tag);
int mpi_tls_recv_bytes(void *buf, size_t count, int src, int tag);
int mpi_tls_isend_bytes(const void *buf, size_t count, int dest, int tag,
        mpi_tls_request_t *request);
int mpi_tls_irecv_bytes(void *buf, size_t count, int src, int tag,
        mpi_tls_request_t *request);
int mpi_tls_wait(mpi_tls_request_t *request);

#endif /* distributed-sgx-sort/enclave/mpi_tls.h */
