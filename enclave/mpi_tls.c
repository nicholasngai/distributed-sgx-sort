#include "enclave/mpi_tls.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
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
#if defined(OE_SIMULATION) || defined(OE_SIMULATION_CERT) || defined(DISTRIBUTED_SGX_SORT_HOSTONLY)
#include "enclave/sim_cert.h"
#endif /* OE_SIMULATION || OE_SIMULATION_CERT || DISTRIBUTED_SGX_SORT_HOSTONLY */

struct mpi_tls_frag_header {
    unsigned char checksum[32]; // TODO Checksum not yet implemented.
};

struct mpi_tls_session {
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_ctr_drbg_context drbg;
    struct {
        uint32_t int_ms;
        uint32_t fin_ms;
    } timing;
    spinlock_t lock;

    /* Used by send and recv callbacks. */
    const unsigned char *in_bio;
    size_t in_bio_len;
    unsigned char *out_bio;
    size_t out_bio_len;
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
    int ret;

    if (session->out_bio_len < len) {
        handle_error_string("Output bio is shorter than DTLS record");
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto exit;
    }
    memcpy(session->out_bio, buf, len);
    session->out_bio += len;
    session->out_bio_len -= len;

    ret = len;

exit:
    return ret;
}

static int recv_callback(void *session_, unsigned char *buf, size_t len,
        uint32_t timeout UNUSED) {
    struct mpi_tls_session *session = session_;
    int ret;

    if (!session->in_bio_len) {
        ret = MBEDTLS_ERR_SSL_WANT_READ;
        goto exit;
    }

    struct {
        uint8_t type     : 8;
        uint16_t version : 16;
        uint16_t epoch   : 16;
        uint64_t seq     : 48;
        uint16_t length  : 16;
    } __attribute__((packed)) *header = (void *) session->in_bio;
    size_t length = ntohs(header->length);

    if (session->in_bio_len < sizeof(*header)) {
        handle_error_string("Input bio is shorter than DTLS header");
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto exit;
    }

    // TODO Some kind of version check would be good.
    //if (ntohs(header->version) != 0xfeff) {
    //    handle_error_string("Unexpected DTLS version: %hx", header->version);
    //    ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
    //    goto exit;
    //}

    size_t bytes_to_copy = sizeof(*header) + length;

    if (session->in_bio_len < bytes_to_copy || len < bytes_to_copy) {
        handle_error_string("Input bio is shorter than DTLS packet");
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto exit;
    }

    memcpy(buf, session->in_bio, bytes_to_copy);
    session->in_bio += bytes_to_copy;
    session->in_bio_len -= bytes_to_copy;

    ret = bytes_to_copy;

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
        mbedtls_entropy_context *entropy) {
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

#if !defined(OE_SIMULATION) && !defined(OE_SIMULATION_CERT) && !defined(DISTRIBUTED_SGX_SORT_HOSTONLY)
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
#else /* OE_SIMULATION || OE_SIMULATION_CERT || DISTRIBUTED_SGX_SORT_HOSTONLY */
    cert_buf = SIM_CERT;
    cert_buf_size = sizeof(SIM_CERT);
    privkey_buf = SIM_PRIVKEY;
    privkey_buf_size = sizeof(SIM_PRIVKEY);
#endif /* !OE_SIMULATION && !OE_SIMULATION_CERT && !DISTRIBUTED_SGX_SORT_HOSTONLY */
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

exit_free_cert_buf:
#if !defined(OE_SIMULATION) && !defined(OE_SIMULATION_CERT) && !defined(DISTRIBUTED_SGX_SORT_HOSTONLY)
    oe_free_attestation_certificate(cert_buf);
exit_free_privkey_buf:
    oe_free_key(privkey_buf, privkey_buf_size, NULL, 0);
exit_free_pubkey_buf:
    oe_free_key(pubkey_buf, pubkey_buf_size, NULL, 0);
exit:
#endif /* !OE_SIMULATION && !OE_SIMULATION_CERT && !DISTRIBUTED_SGX_SORT_HOSTONLY */
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
                entropy);
        if (ret) {
            handle_error_string("Failed to initialize TLS session structures");
            for (int j = 0; j < i; j++) {
                free_session(&sessions[j]);
            }
            free(sessions);
            goto exit_free_keys;
        }
    }

    /* Allocate buffers for handshakes. */
    struct {
        ocall_mpi_request_t recv;
        bool recv_valid;
        unsigned char *in_bio;
        unsigned char *out_bio;
        size_t in_bio_len;
        size_t out_bio_len;
    } *requests = calloc(world_size, sizeof(*requests));
    if (!requests) {
        goto exit_free_sessions;
    }
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            continue;
        }

        ret = mbedtls_ssl_get_max_out_record_payload(&sessions[i].ssl);
        if (ret < 0) {
            handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
            for (int j = 0; j < i; j++) {
                if (j == world_rank) {
                    continue;
                }
                free(requests[i].in_bio);
            }
            goto exit_free_requests;
        }
        size_t max_payload_len = ret;
        ret = mbedtls_ssl_get_record_expansion(&sessions[i].ssl);
        if (ret < 0) {
            handle_mbedtls_error(ret, "mbedtls_ssl_get_record_expansion");
            for (int j = 0; j < i; j++) {
                if (j == world_rank) {
                    continue;
                }
                free(requests[i].in_bio);
            }
            goto exit_free_requests;
        }
        size_t max_record_len = max_payload_len + ret;
        requests[i].in_bio_len = max_record_len;
        requests[i].out_bio_len = max_record_len;
        requests[i].in_bio = malloc(requests[i].in_bio_len);
        if (!requests[i].in_bio) {
            perror("malloc handshake input bio");
            for (int j = 0; j < i; j++) {
                if (j == world_rank) {
                    continue;
                }
                free(requests[i].in_bio);
                free(requests[i].out_bio);
            }
            goto exit_free_requests;
        }
        requests[i].out_bio = malloc(requests[i].out_bio_len);
        if (!requests[i].out_bio) {
            perror("malloc handshake output bio");
            free(requests[i].in_bio);
            for (int j = 0; j < i; j++) {
                if (j == world_rank) {
                    continue;
                }
                free(requests[i].in_bio);
                free(requests[i].out_bio);
            }
            goto exit_free_requests;
        }

        sessions[i].in_bio_len = 0;
        sessions[i].out_bio = requests[i].out_bio;
        sessions[i].out_bio_len = requests[i].out_bio_len;
    }

    /* Handshake with all elems. Reepatedly loop until all handshakes are
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
            sessions[i].out_bio = requests[i].out_bio;
            sessions[i].out_bio_len = requests[i].out_bio_len;
            ret = mbedtls_ssl_handshake_step(&sessions[i].ssl);
            if (ret && ret != MBEDTLS_ERR_SSL_WANT_READ
                    && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                handle_mbedtls_error(ret, "mbedtls_ssl_handshake_step");
                goto exit_free_bios;
            }

            /* Perform receive if necessary. */
            if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
                int ready = true;
                ocall_mpi_status_t status;

                /* Try wait on handshake bytes. */
                if (requests[i].recv_valid) {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
                    oe_result_t result =
                        ocall_mpi_try_wait(&ret, requests[i].in_bio,
                                requests[i].in_bio_len, &requests[i].recv,
                                &ready, &status);
                    if (result != OE_OK) {
                        handle_oe_error(ret, "ocall_mpi_try_wait");
                        goto exit_free_bios;
                    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
                    ret =
                        ocall_mpi_try_wait(requests[i].in_bio,
                                requests[i].in_bio_len, &requests[i].recv,
                                &ready, &status);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
                    if (ret) {
                        handle_error_string(
                                "Error waiting on receive for handshake");
                        goto exit_free_bios;
                    }
                    if (ready) {
                        sessions[i].in_bio = requests[i].in_bio;
                        sessions[i].in_bio_len = status.count;
                        requests[i].recv_valid = false;
                    }
                }

                /* Execute next receive if able. */
                if (!requests[i].recv_valid && !sessions[i].in_bio_len) {
                    /* Perform async receive. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
                    oe_result_t result =
                        ocall_mpi_irecv_bytes(&ret, requests[i].in_bio_len, i,
                                0, &requests[i].recv);
                    if (result != OE_OK) {
                        handle_oe_error(ret, "ocall_mpi_irecv_bytes");
                        goto exit_free_bios;
                    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
                    ret =
                        ocall_mpi_irecv_bytes(requests[i].in_bio_len, i, 0,
                                &requests[i].recv);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
                    if (ret) {
                        handle_error_string(
                                "Error posting receive for handshake");
                        goto exit_free_bios;
                    }
                    requests[i].recv_valid = true;
                }
            }

            /* Perform send if necessary. */
            if (sessions[i].out_bio_len < requests[i].out_bio_len) {
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
                oe_result_t result =
                    ocall_mpi_send_bytes(&ret, requests[i].out_bio,
                            requests[i].out_bio_len - sessions[i].out_bio_len,
                            i, 0);
                if (result != OE_OK) {
                    handle_oe_error(ret, "ocall_mpi_send_bytes");
                    goto exit_free_bios;
                }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
                ret =
                    ocall_mpi_send_bytes(requests[i].out_bio,
                            requests[i].out_bio_len - sessions[i].out_bio_len,
                            i, 0);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
                if (ret) {
                    handle_error_string("Error sending handshake");
                    goto exit_free_bios;
                }
                sessions[i].out_bio = requests[i].out_bio;
                sessions[i].out_bio_len = requests[i].out_bio_len;
            }
        }
    } while (!all_init_finished);

    /* Free buffers used for handshake. */
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            continue;
        }
        free(requests[i].in_bio);
        free(requests[i].out_bio);
    }
    free(requests);

    ocall_mpi_barrier();

    return 0;

exit_free_bios:
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            continue;
        }
        free(requests[i].in_bio);
        free(requests[i].out_bio);
    }
exit_free_requests:
    free(requests);
exit_free_sessions:
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            continue;
        }
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

static int send_to_bio(struct mpi_tls_session *session,
        const struct mpi_tls_frag_header *header, const void *in_,
        size_t in_len, unsigned char *bio, size_t bio_len, size_t *bio_used) {
    const unsigned char *in = in_;
    int ret;

    ret = mbedtls_ssl_get_max_out_record_payload(&session->ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit;
    }
    size_t max_payload_len = ret;

    spinlock_lock(&session->lock);

    /* Send header. */
    session->out_bio = bio;
    session->out_bio_len = bio_len;
    ret =
        mbedtls_ssl_write(&session->ssl, (const unsigned char *) header,
                sizeof(*header));
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_write");
        goto exit;
    }

    /* Send data. */
    while (in_len) {
        size_t bytes_to_write = MIN(in_len, max_payload_len);
        ret = mbedtls_ssl_write(&session->ssl, in, bytes_to_write);
        if (ret < 0) {
            handle_mbedtls_error(ret, "mbedtls_ssl_write");
            goto exit;
        }
        in += ret;
        in_len -= ret;
    }

    *bio_used = bio_len - session->out_bio_len;

    spinlock_unlock(&session->lock);

    ret = 0;

exit:
    return ret;
}

static int recv_from_bio(struct mpi_tls_session *session,
        const unsigned char *bio, size_t bio_len,
        struct mpi_tls_frag_header *header, void *out_, size_t out_len,
        size_t *bytes_read) {
    unsigned char *out = out_;
    int ret;

    ret = mbedtls_ssl_get_max_out_record_payload(&session->ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit;
    }
    size_t max_payload_len = ret;

    spinlock_lock(&session->lock);

    /* Receive header. */
    session->in_bio = bio;
    session->in_bio_len = bio_len;
    ret =
        mbedtls_ssl_read(&session->ssl, (unsigned char *) header,
                sizeof(*header));
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_read");
        goto exit;
    }

    /* Receive data. */
    *bytes_read = 0;
    size_t bytes_remaining = out_len;
    while (bytes_remaining) {
        ret =
            mbedtls_ssl_read(&session->ssl, out,
                    MAX(bytes_remaining, max_payload_len));
        if (ret == MBEDTLS_ERR_SSL_WANT_READ) {
            break;
        }
        if (ret < 0) {
            handle_mbedtls_error(ret, "mbedtls_ssl_read");
            goto exit;
        }

        if ((size_t) ret > bytes_remaining) {
            handle_error_string("Message is longer than buffer");
            goto exit;
        }
        out += ret;
        bytes_remaining -= ret;
    }

    spinlock_unlock(&session->lock);

    *bytes_read = out_len - bytes_remaining;

    ret = 0;

exit:
    return ret;
}

int mpi_tls_send_bytes(const void *buf, size_t count, int dest, int tag) {
    struct mpi_tls_session *session = &sessions[dest];
    int ret = -1;

    spinlock_lock(&session->lock);

    ret = mbedtls_ssl_get_max_out_record_payload(&session->ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit;
    }
    size_t max_payload_len = ret;

    spinlock_unlock(&session->lock);

    /* Allocate bio. */
    struct mpi_tls_frag_header header;
    memset(&header, '\0', sizeof(header)); // TODO
    size_t num_frags = CEIL_DIV(count, max_payload_len) + 1;
    size_t bio_len = count + sizeof(header) + max_payload_len * num_frags;
    unsigned char *bio = malloc(bio_len);
    if (!bio) {
        perror("malloc bio");
        goto exit;
    }

    /* Send message to bio. */
    size_t bio_used;
    ret =
        send_to_bio(session, &header, buf, count, bio, bio_len, &bio_used);
    if (ret) {
        handle_error_string("Error sending DTLS message to bio");
        goto exit_free_bio;
    }

    /* Send bio over MPI. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result = ocall_mpi_send_bytes(&ret, bio, bio_used, dest, tag);
    if (result != OE_OK) {
        handle_oe_error(ret, "ocall_mpi_send_bytes");
        goto exit_free_bio;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret = ocall_mpi_send_bytes(bio, bio_used, dest, tag);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error sending DTLS bytes");
        goto exit;
    }

exit_free_bio:
    free(bio);
exit:
    return ret;
}

int mpi_tls_recv_bytes(void *buf, size_t count, int src, int tag,
        mpi_tls_status_t *status) {
    struct mpi_tls_session *session =
        &sessions[src != OCALL_MPI_ANY_SOURCE ? src : world_rank == 0];
    int ret = -1;

    mpi_tls_status_t ignored_status;
    if (status == MPI_TLS_STATUS_IGNORE) {
        status = &ignored_status;
    }
    if (src == MPI_TLS_ANY_SOURCE) {
        src = OCALL_MPI_ANY_SOURCE;
    }
    if (tag == MPI_TLS_ANY_TAG) {
        tag = OCALL_MPI_ANY_TAG;
    }

    spinlock_lock(&session->lock);

    ret = mbedtls_ssl_get_max_out_record_payload(&session->ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit;
    }
    size_t max_payload_len = ret;

    ret = mbedtls_ssl_get_record_expansion(&session->ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_record_expansion");
        goto exit;
    }
    size_t max_record_len = max_payload_len + ret;

    spinlock_unlock(&session->lock);

    /* Allocate bio. */
    struct mpi_tls_frag_header header; // TODO
    size_t num_frags = CEIL_DIV(count, max_payload_len) + 1;
    size_t bio_len = count + sizeof(header) + max_record_len * num_frags;
    unsigned char *bio = malloc(bio_len);
    if (!bio) {
        perror("malloc bio");
        goto exit;
    }

    /* Receive bio over MPI. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_recv_bytes(&ret, bio, bio_len, src, tag, status);
    if (result != OE_OK) {
        handle_oe_error(ret, "ocall_mpi_recv_bytes");
        goto exit_free_bio;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret = ocall_mpi_recv_bytes(bio, bio_len, src, tag, status);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error receiving DTLS bytes");
        goto exit;
    }

    size_t bytes_read;
    ret =
        recv_from_bio(&sessions[status->source], bio, status->count, &header,
                buf, count, &bytes_read);
    if (ret) {
        handle_error_string("Error receiving DTLS message from bio");
        goto exit_free_bio;
    }
    status->count = bytes_read;

exit_free_bio:
    free(bio);
exit:
    return ret;
}

int mpi_tls_isend_bytes(const void *buf_, size_t count, int dest, int tag,
        mpi_tls_request_t *request) {
    struct mpi_tls_session *session = &sessions[dest];
    const unsigned char *buf = buf_;
    int ret = -1;

    spinlock_lock(&session->lock);

    ret = mbedtls_ssl_get_max_out_record_payload(&session->ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit;
    }
    size_t max_payload_len = ret;

    spinlock_unlock(&session->lock);

    /* Allocate bio. */
    struct mpi_tls_frag_header header;
    memset(&header, '\0', sizeof(header)); // TODO
    size_t num_frags = CEIL_DIV(count, max_payload_len) + 1;
    request->bio_len = count + sizeof(header) + max_payload_len * num_frags;
    request->bio = malloc(request->bio_len);
    if (!request->bio) {
        perror("malloc bio");
        goto exit;
    }

    request->type = MPI_TLS_SEND;

    /* Send message to bio. */
    size_t bio_used;
    ret =
        send_to_bio(session, &header, buf, count, request->bio,
                request->bio_len, &bio_used);
    if (ret) {
        handle_error_string("Error sending DTLS message to bio");
        goto exit_free_bio;
    }

    /* Send bio over MPI. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_isend_bytes(&ret, request->bio, bio_used, dest, tag,
                &request->mpi_request);
    if (result != OE_OK) {
        handle_oe_error(ret, "ocall_mpi_send_bytes");
        goto exit_free_bio;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret =
        ocall_mpi_isend_bytes(request->bio, bio_used, dest, tag,
                &request->mpi_request);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error sending DTLS bytes");
        goto exit;
    }

exit:
    return ret;

exit_free_bio:
    free(request->bio);
    return ret;
}

int mpi_tls_irecv_bytes(void *buf_, size_t count, int src, int tag,
        mpi_tls_request_t *request) {
    struct mpi_tls_session *session =
        &sessions[src != OCALL_MPI_ANY_SOURCE ? src : world_rank == 0];
    unsigned char *buf = buf_;
    int ret = -1;

    spinlock_lock(&session->lock);

    ret = mbedtls_ssl_get_max_out_record_payload(&session->ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit;
    }
    size_t max_payload_len = ret;

    ret = mbedtls_ssl_get_record_expansion(&session->ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_record_expansion");
        goto exit;
    }
    size_t max_record_len = max_payload_len + ret;

    spinlock_unlock(&session->lock);

    if (src == MPI_TLS_ANY_SOURCE) {
        src = OCALL_MPI_ANY_SOURCE;
    }
    if (tag == MPI_TLS_ANY_TAG) {
        tag = OCALL_MPI_ANY_TAG;
    }

    struct mpi_tls_frag_header header; // TODO
    size_t num_frags = CEIL_DIV(count, max_payload_len) + 1;
    request->bio_len = count + sizeof(header) + max_record_len * num_frags;
    request->bio = calloc(1, request->bio_len);
    if (!request->bio) {
        perror("malloc bio");
        goto exit;
    }

    request->buf = buf;
    request->type = MPI_TLS_RECV;
    request->count = count;

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_irecv_bytes(&ret, request->bio_len, src, tag,
                &request->mpi_request);
    if (result != OE_OK) {
        handle_oe_error(result, "ocall_mpi_irecv_bytes");
        ret = result;
        goto exit_free_bio;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret =
        ocall_mpi_irecv_bytes(request->bio_len, src, tag,
                &request->mpi_request);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error posting receive for DTLS bytes");
        goto exit_free_bio;
    }

exit:
    return ret;

exit_free_bio:
    return ret;
}

int mpi_tls_wait(mpi_tls_request_t *request, mpi_tls_status_t *status) {
    int ret;

    mpi_tls_status_t ignored_status;
    if (status == MPI_TLS_STATUS_IGNORE) {
        status = &ignored_status;
    }

    unsigned char *wait_bio;
    size_t wait_bio_len;
    switch (request->type) {
    case MPI_TLS_NULL:
    case MPI_TLS_SEND:
        wait_bio = NULL;
        wait_bio_len = 0;
        break;
    case MPI_TLS_RECV:
        wait_bio = request->bio;
        wait_bio_len = request->bio_len;
        break;
    }

    ocall_mpi_request_t mpi_request;
    if (request->type == MPI_TLS_NULL) {
        mpi_request = OCALL_MPI_REQUEST_NULL;
    } else {
        mpi_request = request->mpi_request;
    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_wait(&ret, wait_bio, wait_bio_len, &mpi_request, status);
    if (result != OE_OK) {
        handle_oe_error(result, "ocall_mpi_wait");
        ret = result;
        goto exit;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret =
        ocall_mpi_wait(wait_bio, wait_bio_len, &mpi_request, status);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error waiting on request");
        goto exit;
    }

    switch (request->type) {
    case MPI_TLS_NULL:
    case MPI_TLS_SEND:
        break;

    case MPI_TLS_RECV: {
        struct mpi_tls_frag_header header;
        size_t bytes_read;
        ret =
            recv_from_bio(&sessions[status->source], request->bio,
                    status->count, &header, request->buf, request->count,
                    &bytes_read);
        if (ret) {
            handle_error_string("Error receiving DTLS message from bio");
            goto exit;
        }
        status->count = bytes_read;
        break;
    }
    }

exit:
    free(request->bio);
    return ret;
}

int mpi_tls_waitany(size_t count, mpi_tls_request_t *requests, size_t *index,
        mpi_tls_status_t *status) {
    int ret;

    mpi_tls_status_t ignored_status;
    if (status == MPI_TLS_STATUS_IGNORE) {
        status = &ignored_status;
    }

    unsigned char *wait_bio = NULL;
    size_t wait_bio_len = 0;
    for (size_t i = 0; i < count; i++) {
        switch (requests[i].type) {
        case MPI_TLS_NULL:
        case MPI_TLS_SEND:
            break;
        case MPI_TLS_RECV:
            if (requests[i].bio_len > wait_bio_len) {
                wait_bio = requests[i].bio;
                wait_bio_len = requests[i].bio_len;
            }
            break;
        }
    }

    ocall_mpi_request_t mpi_requests[count];
    for (size_t i = 0; i < count; i++) {
        if (requests[i].type == MPI_TLS_NULL) {
            mpi_requests[i] = OCALL_MPI_REQUEST_NULL;
        } else {
            mpi_requests[i] = requests[i].mpi_request;
        }

    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_waitany(&ret, wait_bio, wait_bio_len, count, mpi_requests,
                index, status);
    if (result != OE_OK) {
        handle_oe_error(result, "ocall_mpi_wait");
        ret = result;
        goto exit;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret =
        ocall_mpi_waitany(wait_bio, wait_bio_len, count, mpi_requests, index,
                status);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error waiting on request");
        goto exit;
    }

    switch (requests[*index].type) {
    case MPI_TLS_NULL:
    case MPI_TLS_SEND:
        break;

    case MPI_TLS_RECV: {
        struct mpi_tls_frag_header header;
        size_t bytes_read;
        ret =
            recv_from_bio(&sessions[status->source], wait_bio, status->count,
                    &header, requests[*index].buf, requests[*index].count,
                    &bytes_read);
        if (ret) {
            handle_error_string("Error receiving DTLS message from bio");
            goto exit;
        }
        status->count = bytes_read;
        break;
    }
    }

exit:
    free(requests[*index].bio);
    return ret;
}
