#include "enclave/mpi_tls.h"
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include <openenclave/enclave.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#endif /* DISTRUBTED_SGX_SORT_HOSTONLY */
#include "common/defs.h"
#include "common/error.h"
#include "common/ocalls.h"
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include "enclave/parallel_t.h"
#endif /* DISTRUBTED_SGX_SORT_HOSTONLY */
#include "enclave/synch.h"

#include <mbedtls/debug.h>

/* Include simulation cert and key data if compiling in simulation mode or
 * hostonly mode. */
#if defined(OE_SIMULATION) || defined(DISTRIBUTED_SGX_SORT_HOSTONLY)
#include "enclave/sim_cert.h"
#endif /* OE_SIMULATION || DISTRIBUTED_SGX_SORT_HOSTONLY */

struct mpi_tls_session {
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_ctr_drbg_context drbg;
    struct {
        uint32_t int_ms;
        uint32_t fin_ms;
    } timing;
    spinlock_t lock;

    /* Parameters used by send and recv callbacks. */
    int rank;
    int tag;
    ocall_mpi_request_t *async;
};

static int world_rank;
static int world_size;
static mbedtls_x509_crt cert;
static mbedtls_pk_context privkey;
static struct mpi_tls_session *sessions;

static int verify_callback(void *data UNUSED, mbedtls_x509_crt *crt UNUSED,
        int depth UNUSED, uint32_t *flags UNUSED) {
    // TODO Implement actual SGX attestation verification.
    return 0;
}

static int send_callback(void *session_, const unsigned char *buf, size_t len) {
    struct mpi_tls_session *session = session_;
    int ret = -1;

    if (session->async) {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        oe_result_t result = ocall_mpi_isend_bytes(&ret, buf, len,
                session->rank, session->tag, session->async);
        if (result != OE_OK) {
            handle_oe_error(result, "ocall_mpi_send_bytes");
            goto exit;
        }
#else /* DISTRUBTED_SGX_SORT_HOSTONLY */
        ret = ocall_mpi_isend_bytes(buf, len, session->rank, session->tag,
                session->async);
#endif /* DISTRUBTED_SGX_SORT_HOSTONLY */
    } else {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        oe_result_t result = ocall_mpi_send_bytes(&ret, buf, len, session->rank,
                session->tag);
        if (result != OE_OK) {
            handle_oe_error(result, "ocall_mpi_send_bytes");
            goto exit;
        }
#else /* DISTRUBTED_SGX_SORT_HOSTONLY */
        ret = ocall_mpi_send_bytes(buf, len, session->rank, session->tag);
#endif /* DISTRUBTED_SGX_SORT_HOSTONLY */
    }
    if (ret) {
        handle_error_string("Failed to send TLS encrypted bytes");
        goto exit;
    }

    ret = len;

exit:
    return ret;
}

static int recv_callback(void *session_, unsigned char *buf, size_t len,
        uint32_t timeout UNUSED) {
    struct mpi_tls_session *session = session_;
    int ret = -1;

    if (session->async) {
        ocall_mpi_status_t status;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        oe_result_t result = ocall_mpi_wait(&ret, buf, len, session->async,
                &status);
        if (result != OE_OK) {
            handle_oe_error(result, "ocall_mpi_try_recv_bytes");
            goto exit;
        }
#else /* DISTRUBTED_SGX_SORT_HOSTONLY */
        ret = ocall_mpi_wait(buf, len, session->async, &status);
#endif /* DISTRUBTED_SGX_SORT_HOSTONLY */
        if (ret) {
            handle_error_string("Failed to receive async TLS encrypted bytes");
            goto exit;
        }
        ret = status.count;
    } else {
        ocall_mpi_status_t status;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        oe_result_t result = ocall_mpi_try_recv_bytes(&ret, buf, len,
                session->rank, session->tag, &status);
        if (result != OE_OK) {
            handle_oe_error(result, "ocall_mpi_try_recv_bytes");
            goto exit;
        }
#else /* DISTRUBTED_SGX_SORT_HOSTONLY */
        ret = ocall_mpi_try_recv_bytes(buf, len, session->rank, session->tag,
                &status);
#endif /* DISTRUBTED_SGX_SORT_HOSTONLY */
        if (ret < 0) {
            handle_error_string("Failed to receive TLS encrypted bytes");
            goto exit;
        }
    }

    if (!ret) {
        ret = MBEDTLS_ERR_SSL_WANT_READ;
    }

exit:
    return ret;
}

static void set_timer_callback(void *session_, uint32_t int_ms,
        uint32_t fin_ms) {
    struct mpi_tls_session *session = session_;
    session->timing.int_ms = int_ms;
    session->timing.fin_ms = fin_ms;
}

static int get_timer_callback(void *session_) {
    struct mpi_tls_session *session = session_;
    return session->timing.fin_ms ? 0 : -1;
}

static int init_session(struct mpi_tls_session *session, bool is_server,
        mbedtls_x509_crt *cert, mbedtls_pk_context *privkey,
        mbedtls_entropy_context *entropy, int rank) {
    int ret = -1;

    /* Initialize DRBG. */
    mbedtls_ctr_drbg_init(&session->drbg);
    ret = mbedtls_ctr_drbg_seed(&session->drbg, mbedtls_entropy_func, entropy,
            NULL, 0);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_ctr_drbg_init");
        goto exit_free_drbg;
    }

    /* Initialize config. */
    // TODO Think about downgrade attacks. All clients will be on the same
    // version, anyway.
    mbedtls_ssl_config_init(&session->conf);
    ret = mbedtls_ssl_config_defaults(&session->conf,
            is_server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_ssl_config_defaults");
        goto exit_free_config;
    }
    mbedtls_ssl_conf_rng(&session->conf, mbedtls_ctr_drbg_random, &session->drbg);
    mbedtls_ssl_conf_authmode(&session->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(&session->conf, verify_callback, NULL);
    mbedtls_ssl_conf_ca_chain(&session->conf, cert->next, NULL);
    ret = mbedtls_ssl_conf_own_cert(&session->conf, cert, privkey);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_ssl_conf_own_cert");
        goto exit_free_config;
    }
    mbedtls_ssl_conf_dtls_cookies(&session->conf, NULL, NULL, NULL);
    // TODO Figure out how to enable this again.
    mbedtls_ssl_conf_dtls_anti_replay(&session->conf,
            MBEDTLS_SSL_ANTI_REPLAY_DISABLED);

    /* Initialize SSL. */
    mbedtls_ssl_init(&session->ssl);
    ret = mbedtls_ssl_setup(&session->ssl, &session->conf);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_ssl_setup");
        goto exit_free_ssl;
    }
    mbedtls_ssl_set_bio(&session->ssl, session, send_callback, NULL,
            recv_callback);
    mbedtls_ssl_set_timer_cb(&session->ssl, session, set_timer_callback,
            get_timer_callback);

    /* Initialize spinlock. */
    spinlock_init(&session->lock);

    /* Initialize rank. */
    session->rank = rank;

    return 0;

exit_free_ssl:
    mbedtls_ssl_free(&session->ssl);
exit_free_config:
    mbedtls_ssl_config_free(&session->conf);
exit_free_drbg:
    mbedtls_ctr_drbg_free(&session->drbg);
    return ret;
}

static void free_session(struct mpi_tls_session *session) {
    mbedtls_ctr_drbg_free(&session->drbg);
    mbedtls_ssl_free(&session->ssl);
    mbedtls_ssl_config_free(&session->conf);
}

static int load_certificate_and_key(mbedtls_x509_crt *cert,
        mbedtls_pk_context *privkey) {
    /* Generate public/private key pair and certificate buffers. */
    unsigned char *cert_buf;
    size_t cert_buf_size;
    unsigned char *privkey_buf;
    size_t privkey_buf_size;
    int ret = -1;

#if !defined(OE_SIMULATION) && !defined(DISTRIBUTED_SGX_SORT_HOSTONLY)
    unsigned char *pubkey_buf;
    size_t pubkey_buf_size;
    oe_result_t result;

    oe_asymmetric_key_params_t key_params;
    key_params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;
    key_params.format = OE_ASYMMETRIC_KEY_PEM;
    key_params.user_data = NULL;
    key_params.user_data_size = 0;
    result = oe_get_public_key_by_policy(OE_SEAL_POLICY_UNIQUE, &key_params,
            &pubkey_buf, &pubkey_buf_size, NULL, 0);
    if (result != OE_OK) {
        handle_oe_error(result, "oe_get_public_key_by_policy");
        goto exit;
    }
    result = oe_get_private_key_by_policy(OE_SEAL_POLICY_UNIQUE, &key_params,
            &privkey_buf, &privkey_buf_size, NULL, 0);
    if (result != OE_OK) {
        handle_oe_error(result, "oe_get_private_key_by_policy");
        goto exit_free_pubkey_buf;
    }
    oe_uuid_t uuid_sgx_ecdsa = { OE_FORMAT_UUID_SGX_ECDSA };
    oe_attester_initialize();
    result = oe_get_attestation_certificate_with_evidence_v2(&uuid_sgx_ecdsa,
            (unsigned char *)
                "C=US,"
                "ST=California,"
                "L=Berkeley,"
                "O=University of California\\, Berkeley,"
                "CN=Distributed SGX Sort",
            privkey_buf, privkey_buf_size, pubkey_buf, pubkey_buf_size, NULL, 0,
            &cert_buf, &cert_buf_size);
    if (result != OE_OK) {
        handle_oe_error(result, "oe_get_attestation_cert_buf_with_evidence_v2");
        goto exit_free_privkey_buf;
    }
#else /* OE_SIMULATION || DISTRIBUTED_SGX_SORT_HOSTONLY */
    cert_buf = SIM_CERT;
    cert_buf_size = sizeof(SIM_CERT);
    privkey_buf = SIM_PRIVKEY;
    privkey_buf_size = sizeof(SIM_PRIVKEY);
#endif /* !OE_SIMULATION && !DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret = mbedtls_x509_crt_parse_der(cert, cert_buf, cert_buf_size);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_x509_crt_parse_der");
        goto exit_free_cert_buf;
    }
    ret = mbedtls_pk_parse_key(privkey, privkey_buf, privkey_buf_size, NULL, 0);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_pk_parse_key");
        goto exit_free_cert_buf;
    }

    ret = 0;

exit_free_cert_buf:
#if !defined(OE_SIMULATION) && !defined(DISTRIBUTED_SGX_SORT_HOSTONLY)
    oe_free_attestation_certificate(cert_buf);
exit_free_privkey_buf:
    oe_free_key(privkey_buf, privkey_buf_size, NULL, 0);
exit_free_pubkey_buf:
    oe_free_key(pubkey_buf, pubkey_buf_size, NULL, 0);
exit:
#endif /* !OE_SIMULATION && !DISTRIBUTED_SGX_SORT_HOSTONLY */
    return ret;
}

int mpi_tls_init(size_t world_rank_, size_t world_size_,
        mbedtls_entropy_context *entropy) {
    int ret = -1;

    world_rank = world_rank_;
    world_size = world_size_;

    /* Load certificate and private key. */
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&privkey);
    if (load_certificate_and_key(&cert, &privkey)) {
        handle_error_string("Failed to load certificate and private key");
        goto exit;
    }

    /* Initialize TLS sessions. */
    sessions = malloc(world_size * sizeof(*sessions));
    if (!sessions) {
        perror("malloc TLS sessions");
        goto exit_free_keys;
    }
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            /* Skip our own rank. */
            continue;
        }

        /* Initialize SSL. We act as clients to lower ranks and servers to
         * higher ranks. */
        ret = init_session(&sessions[i], i > world_rank, &cert, &privkey,
                entropy, i);
        if (ret) {
            handle_error_string("Failed to initialize TLS session structures");
            for (int j = 0; j < i; j++) {
                free_session(&sessions[j]);
            }
            free(sessions);
            goto exit_free_keys;
        }

        /* Use tag of 0 for SSL handshake. */
        sessions[i].tag = 0;
        sessions[i].async = NULL;
    }

    /* Handshake with all nodes. Reepatedly loop until all handshakes are
     * finished. */
    bool all_init_finished;
    do {
        all_init_finished = true;
        for (int i = 0; i < world_size; i++) {
            /* Skip our own rank. */
            if (i == world_rank) {
                continue;
            }

            /* Skip if handshake finished. */
            if (sessions[i].ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER) {
                continue;
            }

            /* Handshake not finished. */
            all_init_finished = false;

            /* Do handshake. */
            ret = mbedtls_ssl_handshake_step(&sessions[i].ssl);
            if (ret && ret != MBEDTLS_ERR_SSL_WANT_READ
                    && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                handle_mbedtls_error(ret, "mbedtls_ssl_handshake_step");
                goto exit_free_sessions;
            }
        }
    } while (!all_init_finished);

    ocall_mpi_barrier();

    return 0;

exit_free_sessions:
    for (int i = 0; i < world_size; i++) {
        free_session(&sessions[i]);
    }
    free(sessions);
exit_free_keys:
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&privkey);
exit:
    return -1;
}

void mpi_tls_free(void) {
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            /* Skip our own rank. */
            continue;
        }
        free_session(&sessions[i]);
    }
    free(sessions);
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&privkey);
}

int mpi_tls_send_bytes(const void *buf_, size_t count, int dest, int tag) {
    const unsigned char *buf = buf_;
    int ret = -1;

    ret = mbedtls_ssl_get_max_out_record_payload(&sessions[dest].ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit;
    }
    size_t max_payload_len = ret;

    size_t bytes_remaining = count;
    while (bytes_remaining) {
        size_t bytes_to_write = MIN(bytes_remaining, max_payload_len);
        /* Only lock if we haven't started sending. Otherwise, we already have
         * the lock and didn't unlock last time (see below). */
        if (bytes_remaining == count) {
            spinlock_lock(&sessions[dest].lock);
        }
        sessions[dest].tag = tag;
        sessions[dest].async = NULL;
        ret = mbedtls_ssl_write(&sessions[dest].ssl, buf, bytes_to_write);
        if (ret < 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ
                && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                handle_mbedtls_error(ret, "mbedtls_ssl_write");
                goto exit;
            }
            ret = 0;
        }
        buf += ret;
        bytes_remaining -= ret;
        /* Only unlock if we haven't started sending or if we are finished.
         * Otherwise, all fragments must be sent atomically. */
        if (bytes_remaining == count || !bytes_remaining) {
            spinlock_unlock(&sessions[dest].lock);
        }
    }

    ret = 0;

exit:
    return ret;
}

int mpi_tls_recv_bytes(void *buf_, size_t count, int src, int tag) {
    unsigned char *buf = buf_;
    int ret = -1;

    ret = mbedtls_ssl_get_max_out_record_payload(&sessions[src].ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit;
    }
    size_t max_payload_len = ret;

    size_t bytes_remaining = count;
    while (bytes_remaining) {
        size_t bytes_to_read = MIN(bytes_remaining, max_payload_len);
        /* Only lock if we haven't started receiving. Otherwise, we already have
         * the lock and didn't unlock last time (see below). */
        if (bytes_remaining == count) {
            spinlock_lock(&sessions[src].lock);
        }
        sessions[src].tag = tag;
        sessions[src].async = NULL;
        ret = mbedtls_ssl_read(&sessions[src].ssl, buf, bytes_to_read);
        if (ret < 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ
                && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                handle_mbedtls_error(ret, "mbedtls_ssl_write");
                goto exit;
            }
            ret = 0;
        }
        buf += ret;
        bytes_remaining -= ret;
        /* Only unlock if we haven't started receiving or if we are finished.
         * Otherwise, all fragments must be sent atomically. */
        if (bytes_remaining == count || !bytes_remaining) {
            spinlock_unlock(&sessions[src].lock);
        }
    }

    ret = 0;

exit:
    return ret;
}

int mpi_tls_isend_bytes(const void *buf_, size_t count, int dest, int tag,
        mpi_tls_request_t *request) {
    const unsigned char *buf = buf_;
    int ret = -1;

    ret = mbedtls_ssl_get_max_out_record_payload(&sessions[dest].ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit;
    }
    size_t max_payload_len = ret;

    request->type = MPI_TLS_SEND;
    request->num_requests = CEIL_DIV(count, max_payload_len);
    request->mpi_requests =
        malloc(request->num_requests * sizeof(*request->mpi_requests));
    if (!request->mpi_requests) {
        perror("malloc mpi_requests");
        ret = errno;
        goto exit;
    }

    size_t bytes_remaining = count;
    for (size_t i = 0; i < request->num_requests; i++) {
        size_t bytes_to_write = MIN(bytes_remaining, max_payload_len);
        /* Only lock if we haven't started sending. Otherwise, we already have
         * the lock and didn't unlock last time (see below). */
        if (bytes_remaining == count) {
            spinlock_lock(&sessions[dest].lock);
        }
        sessions[dest].tag = tag;
        sessions[dest].async = &request->mpi_requests[i];
        ret = mbedtls_ssl_write(&sessions[dest].ssl, buf, bytes_to_write);
        if (ret < 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ
                && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                handle_mbedtls_error(ret, "mbedtls_ssl_write");
                goto exit;
            }
            ret = 0;
        }
        buf += ret;
        bytes_remaining -= ret;
        /* Only unlock if we haven't started sending or if we are finished.
         * Otherwise, all fragments must be sent atomically. */
        if (bytes_remaining == count || !bytes_remaining) {
            spinlock_unlock(&sessions[dest].lock);
        }
    }

    ret = 0;

exit:
    return ret;
}

int mpi_tls_irecv_bytes(void *buf_, size_t count, int src, int tag,
        mpi_tls_request_t *request) {
    unsigned char *buf = buf_;
    int ret = -1;

    ret = mbedtls_ssl_get_max_out_record_payload(&sessions[src].ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit;
    }
    size_t max_payload_len = ret;

    ret = mbedtls_ssl_get_record_expansion(&sessions[src].ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_record_expansion");
        goto exit;
    }
    size_t max_record_len = max_payload_len + ret;

    request->type = MPI_TLS_RECV;
    request->num_requests = CEIL_DIV(count, max_payload_len);
    request->mpi_requests =
        malloc(request->num_requests * sizeof(*request->mpi_requests));
    if (!request->mpi_requests) {
        perror("malloc mpi_requests");
        ret = errno;
        goto exit;
    }
    request->buf = buf;
    request->count = count;
    request->rank = src;
    request->tag = tag;

    spinlock_lock(&sessions[request->rank].lock);
    for (size_t i = 0; i < request->num_requests; i++) {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        oe_result_t result = ocall_mpi_irecv_bytes(&ret, max_record_len,
                request->rank, request->tag, &request->mpi_requests[i]);
        if (result != OE_OK) {
            handle_oe_error(result, "ocall_mpi_wait");
            ret = result;
            goto exit_free_requests;
        }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        ret = ocall_mpi_irecv_bytes(max_record_len, request->rank, request->tag,
                &request->mpi_requests[i]);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    }
    spinlock_unlock(&sessions[request->rank].lock);

    ret = 0;
    goto exit;

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
exit_free_requests:
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    free(request->mpi_requests);
exit:
    return ret;
}

int mpi_tls_wait(mpi_tls_request_t *request) {
    ocall_mpi_status_t status;
    int ret;

    switch (request->type) {
    case MPI_TLS_SEND:
        for (size_t i = 0; i < request->num_requests; i++) {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
            oe_result_t result = ocall_mpi_wait(&ret, request->buf,
                    request->count, &request->mpi_requests[i], &status);
            if (result != OE_OK) {
                handle_oe_error(result, "ocall_mpi_wait");
                ret = result;
                goto exit;
            }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
            ret = ocall_mpi_wait(request->buf, request->count,
                    &request->mpi_requests[i], &status);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
            if (ret) {
                handle_error_string("Error waiting on isend request");
                goto exit;
            }
        }
        break;

    case MPI_TLS_RECV:
        ret =
            mbedtls_ssl_get_max_out_record_payload(
                    &sessions[request->rank].ssl);
        if (ret < 0) {
            handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
            goto exit;
        }
        size_t max_payload_len = ret;

        size_t bytes_remaining = request->count;
        for (size_t i = 0; i < request->num_requests; i++) {
            size_t bytes_to_read = MIN(bytes_remaining, max_payload_len);
            spinlock_lock(&sessions[request->rank].lock);
            sessions[request->rank].tag = request->tag;
            sessions[request->rank].async = &request->mpi_requests[i];
            ret = mbedtls_ssl_read(&sessions[request->rank].ssl, request->buf,
                    bytes_to_read);
            spinlock_unlock(&sessions[request->rank].lock);
            if (ret < 0) {
                if (ret != MBEDTLS_ERR_SSL_WANT_READ
                    && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                    handle_mbedtls_error(ret, "mbedtls_ssl_read");
                    goto exit;
                }
                ret = 0;
            }
            request->buf += ret;
            bytes_remaining -= ret;
        }
        break;
    }

    ret = 0;

exit:
    free(request->mpi_requests);
    return ret;
}
