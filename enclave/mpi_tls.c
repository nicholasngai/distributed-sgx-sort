#include "mpi_tls.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openenclave/enclave.h>
#include "parallel_t.h"

struct mpi_tls_session {
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;
};

static size_t world_rank;
static size_t world_size;
static SSL_CTX *ctx;
static struct mpi_tls_session *sessions;

static int init_session(struct mpi_tls_session *session) {
    session->ssl = SSL_new(ctx);
    if (!session->ssl) {
        goto exit;
    }

    session->rbio = BIO_new(BIO_s_mem());
    if (!session->rbio) {
        goto exit_free_ssl;
    }

    session->wbio = BIO_new(BIO_s_mem());
    if (!session->wbio) {
        goto exit_free_rbio;
    }

    SSL_set_bio(session->ssl, session->rbio, session->wbio);

    return 0;

exit_free_rbio:
    BIO_free_all(session->rbio);
exit_free_ssl:
    SSL_free(session->ssl);
exit:
    return -1;
}

static void free_session(struct mpi_tls_session *session) {
    SSL_free(session->ssl);
    /* The BIOs are already freed by SSL_free. */
}

int mpi_tls_init(size_t world_rank_, size_t world_size_) {
    world_rank = world_rank_;
    world_size = world_size_;

    /* Initialize global context. */
    // TODO Think about downgrade attacks. All clients will be on the same
    // version, anyway.
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (!ctx) {
        goto exit;
    }

    /* Initialize TLS sessions. */
    sessions = malloc(world_size * sizeof(*sessions));
    if (!sessions) {
        goto exit_free_ctx;
    }
    for (size_t i = 0; i < world_size; i++) {
        if (i == world_size) {
            /* Skip our own rank and zero out all memory. */
            memset(&sessions[i], '\0', sizeof(sessions[i]));
            continue;
        }

        int ret = init_session(&sessions[i]);
        if (ret) {
            for (size_t j = 0; j < i; j++) {
                free_session(&sessions[j]);
            }
            free(sessions);
            goto exit_free_ctx;
        }

        /* We act as clients to lower ranks and servers to higher ranks. */
        if (i > world_rank) {
            SSL_set_accept_state(sessions[i].ssl);
        }
    }

    return 0;

    for (size_t i = 0; i < world_size; i++) {
        free_session(&sessions[i]);
    }
    free(sessions);
exit_free_ctx:
    SSL_CTX_free(ctx);
exit:
    return -1;
}

void mpi_tls_free(void) {
    for (size_t i = 0; i < world_size; i++) {
        free_session(&sessions[i]);
    }
    free(sessions);
    SSL_CTX_free(ctx);
}

int mpi_tls_send_bytes(const unsigned char *buf, size_t count, int dest,
        int tag) {
    oe_result_t result;
    int ret = -1;
    result = ocall_mpi_send_bytes(&ret, buf, count, dest, tag);
    if (result != OE_OK || ret) {
        fprintf(stderr, "ocall_mpi_send_bytes: %s\n", oe_result_str(result));
    }
    return ret;
}

int mpi_tls_recv_bytes(unsigned char *buf, size_t count, int src, int tag) {
    oe_result_t result;
    int ret = -1;
    result = ocall_mpi_recv_bytes(&ret, buf, count, src, tag);
    if (result != OE_OK || ret) {
        fprintf(stderr, "ocall_mpi_recv_bytes: %s\n", oe_result_str(result));
    }
    return ret;
}
