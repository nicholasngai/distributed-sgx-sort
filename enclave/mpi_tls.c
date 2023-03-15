#include "enclave/mpi_tls.h"
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>
#include "common/crypto.h"
#include "common/defs.h"
#include "common/error.h"
#include "common/ocalls.h"

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
#include <openenclave/enclave.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include "enclave/parallel_t.h"
#endif /* DISTRUBTED_SGX_SORT_HOSTONLY */

/* Include simulation cert and key data if compiling in simulation mode or
 * hostonly mode. */
#if defined(OE_SIMULATION) || defined(OE_SIMULATION_CERT) || defined(DISTRIBUTED_SGX_SORT_HOSTONLY)
#include "enclave/sim_cert.h"
#endif /* OE_SIMULATION || OE_SIMULATION_CERT || DISTRIBUTED_SGX_SORT_HOSTONLY */

struct mpi_tls_session {
    /* Keys for encryption/authentication. */
    unsigned char send_key[KEY_LEN];
    unsigned char recv_key[KEY_LEN];
};

struct mpi_tls_handshake_session {
    int other_rank;
    mbedtls_ssl_config conf;
    mbedtls_ssl_context ssl;
    mbedtls_ctr_drbg_context drbg;
    unsigned char *recv_buf;
    size_t recv_buf_idx;
    size_t recv_buf_len;
    size_t recv_buf_cap;

    struct mpi_tls_session *session;
};

static int world_rank;
static int world_size;
static mbedtls_x509_crt cert;
static mbedtls_pk_context privkey;
static struct mpi_tls_session *sessions;

static int ciphersuites[] = {
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    0,
};

/* Bandwidth measurement. */
size_t mpi_tls_bytes_sent;

static int verify_callback(void *data UNUSED, mbedtls_x509_crt *crt UNUSED,
        int depth UNUSED, uint32_t *flags UNUSED) {
    // TODO Implement actual SGX attestation verification.
    return 0;
}

/* Send callback, used only for the handshake. */
static int send_callback(void *hs_session_, const unsigned char *buf,
        size_t len) {
    struct mpi_tls_handshake_session *hs_session = hs_session_;
    int ret;

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_send_bytes(&ret, buf, len, hs_session->other_rank, 0);
    if (result != OE_OK) {
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        handle_oe_error(result, "ocall_mpi_send_bytes");
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret = ocall_mpi_send_bytes(buf, len, hs_session->other_rank, 0);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error sending TLS handshake bytes from %d to %d",
                world_rank, hs_session->other_rank);
        ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
        goto exit;
    }

    __atomic_add_fetch(&mpi_tls_bytes_sent, len, __ATOMIC_RELAXED);

    ret = len;

exit:
    return ret;
}

/* Receive callback, used only for the handshake. */
static int recv_callback(void *hs_session_, unsigned char *buf, size_t len,
        uint32_t timeout UNUSED) {
    struct mpi_tls_handshake_session *hs_session = hs_session_;
    size_t bytes_received = 0;
    int ret;

    /* If there are still bytes in the receive buffer, copy those first. */
    if (hs_session->recv_buf_idx < hs_session->recv_buf_len) {
        size_t bytes_to_copy =
            MIN(len, hs_session->recv_buf_len - hs_session->recv_buf_idx);
        memcpy(buf, hs_session->recv_buf + hs_session->recv_buf_idx,
                bytes_to_copy);
        buf += bytes_to_copy;
        hs_session->recv_buf_idx += bytes_to_copy;
        len -= bytes_to_copy;
        bytes_received += bytes_to_copy;
    }

    /* While there are any more bytes to receive, keep receiving. */
    while (len > 0) {
        ocall_mpi_status_t status;
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
        oe_result_t result =
            ocall_mpi_recv_bytes(&ret, hs_session->recv_buf,
                    hs_session->recv_buf_cap, hs_session->other_rank, 0,
                    &status);
        if (result != OE_OK) {
            ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            handle_oe_error(result, "ocall_mpi_recv_bytes");
        }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        ret =
            ocall_mpi_recv_bytes(hs_session->recv_buf, hs_session->recv_buf_cap,
                    hs_session->other_rank, 0, &status);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
        if (ret) {
            handle_error_string(
                    "Error receiving TLS handshake bytes from %d into %d",
                    hs_session->other_rank, world_rank);
            ret = MBEDTLS_ERR_SSL_INTERNAL_ERROR;
            goto exit;
        }

        hs_session->recv_buf_idx = 0;
        hs_session->recv_buf_len = status.count;

        if (hs_session->recv_buf_idx < hs_session->recv_buf_len) {
            size_t bytes_to_copy =
                MIN(len, hs_session->recv_buf_len - hs_session->recv_buf_idx);
            memcpy(buf, hs_session->recv_buf + hs_session->recv_buf_idx,
                    bytes_to_copy);
            buf += bytes_to_copy;
            hs_session->recv_buf_idx += bytes_to_copy;
            len -= bytes_to_copy;
            bytes_received += bytes_to_copy;
        }
    }

    ret = bytes_received;

exit:
    return ret;
}

static int export_keys_callback(void *hs_session_,
        const unsigned char *master_secret UNUSED,
        const unsigned char *key_block, size_t mac_len, size_t key_len,
        size_t iv_len UNUSED) {
    struct mpi_tls_handshake_session *hs_session = hs_session_;
    int ret;

    assert(key_len == sizeof(hs_session->session->send_key));
    assert(key_len == sizeof(hs_session->session->recv_key));

    if (hs_session->other_rank > world_rank) {
        memcpy(hs_session->session->send_key, key_block + mac_len * 2,
                sizeof(hs_session->session->send_key));
        memcpy(hs_session->session->recv_key, key_block + mac_len * 2 + key_len,
                sizeof(hs_session->session->recv_key));
    } else {
        memcpy(hs_session->session->send_key, key_block + mac_len * 2 + key_len,
                sizeof(hs_session->session->send_key));
        memcpy(hs_session->session->recv_key, key_block + mac_len * 2,
                sizeof(hs_session->session->recv_key));
    }

    ret = 0;

    return ret;
}

static int init_handshake_session(struct mpi_tls_handshake_session *hs_session,
        int other_rank, struct mpi_tls_session *session, mbedtls_x509_crt *cert,
        mbedtls_pk_context *privkey, mbedtls_entropy_context *entropy) {
    int ret;

    hs_session->other_rank = other_rank;
    hs_session->session = session;

    /* Initialize DRBG. */
    mbedtls_ctr_drbg_init(&hs_session->drbg);
    ret =
        mbedtls_ctr_drbg_seed(&hs_session->drbg, mbedtls_entropy_func, entropy,
                NULL, 0);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_ctr_drbg_init");
        goto exit_free_drbg;
    }

    /* Initialize config. We act as clients to lower ranks and servers to higher
     * ranks. */
    // TODO Think about downgrade attacks. All clients will be on the same
    // version, anyway.
    mbedtls_ssl_config_init(&hs_session->conf);
    ret = mbedtls_ssl_config_defaults(&hs_session->conf,
            other_rank > world_rank
                ? MBEDTLS_SSL_IS_SERVER
                : MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_ssl_config_defaults");
        goto exit_free_config;
    }
    mbedtls_ssl_conf_rng(&hs_session->conf, mbedtls_ctr_drbg_random,
            &hs_session->drbg);
    mbedtls_ssl_conf_authmode(&hs_session->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_verify(&hs_session->conf, verify_callback, NULL);
    mbedtls_ssl_conf_ca_chain(&hs_session->conf, cert->next, NULL);
    ret = mbedtls_ssl_conf_own_cert(&hs_session->conf, cert, privkey);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_ssl_conf_own_cert");
        goto exit_free_config;
    }
    mbedtls_ssl_conf_ciphersuites(&hs_session->conf, ciphersuites);
    mbedtls_ssl_conf_export_keys_cb(&hs_session->conf, export_keys_callback,
            hs_session);

    /* Initialize SSL. */
    mbedtls_ssl_init(&hs_session->ssl);
    ret = mbedtls_ssl_setup(&hs_session->ssl, &hs_session->conf);
    if (ret) {
        handle_mbedtls_error(ret, "mbedtls_ssl_setup");
        goto exit_free_ssl;
    }
    mbedtls_ssl_set_bio(&hs_session->ssl, hs_session, send_callback, NULL,
            recv_callback);

    /* Allocate a buffer in case the message is longer than the requested
     * bytes. */
    ret = mbedtls_ssl_get_max_out_record_payload(&hs_session->ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_max_out_record_payload");
        goto exit_free_ssl;
    }
    size_t max_payload_len = ret;
    ret = mbedtls_ssl_get_record_expansion(&hs_session->ssl);
    if (ret < 0) {
        handle_mbedtls_error(ret, "mbedtls_ssl_get_record_expansion");
        goto exit_free_ssl;
    }
    hs_session->recv_buf_cap = max_payload_len + ret;
    hs_session->recv_buf = malloc(hs_session->recv_buf_cap);
    if (!hs_session->recv_buf) {
        perror("malloc hs_session->recv_buf");
        ret = -1;
        goto exit_free_ssl;
    }
    hs_session->recv_buf_idx = 0;
    hs_session->recv_buf_len = 0;

    return 0;

exit_free_ssl:
    mbedtls_ssl_free(&hs_session->ssl);
exit_free_config:
    mbedtls_ssl_config_free(&hs_session->conf);
exit_free_drbg:
    mbedtls_ctr_drbg_free(&hs_session->drbg);
    return ret;
}

static void free_handshake_session(struct mpi_tls_handshake_session *session) {
    mbedtls_ctr_drbg_free(&session->drbg);
    mbedtls_ssl_free(&session->ssl);
    mbedtls_ssl_config_free(&session->conf);
    free(session->recv_buf);
}

static int load_certificate_and_key(mbedtls_x509_crt *cert,
        mbedtls_pk_context *privkey) {
    /* Generate public/private key pair and certificate buffers. */
    unsigned char *cert_buf;
    size_t cert_buf_size;
    unsigned char *privkey_buf;
    size_t privkey_buf_size;
    int ret;

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
        ret = -1;
        goto exit;
    }
    result = oe_get_private_key_by_policy(OE_SEAL_POLICY_UNIQUE, &key_params,
            &privkey_buf, &privkey_buf_size, NULL, 0);
    if (result != OE_OK) {
        handle_oe_error(result, "oe_get_private_key_by_policy");
        ret = -1;
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
        ret = -1;
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
    int ret;

    world_rank = world_rank_;
    world_size = world_size_;

    /* Load certificate and private key. */
    mbedtls_x509_crt_init(&cert);
    mbedtls_pk_init(&privkey);
    if (load_certificate_and_key(&cert, &privkey)) {
        handle_error_string("Failed to load certificate and private key");
        ret = -1;
        goto exit;
    }

    /* Allocate sessions. */
    sessions = malloc(world_size * sizeof(*sessions));
    if (!sessions) {
        perror("malloc encrypted MPI sessions");
        ret = -1;
        goto exit_free_keys;
    }

    /* Initialize TLS handshake sessions. */
    struct mpi_tls_handshake_session *handshake_sessions =
        malloc(world_size * sizeof(*handshake_sessions));
    if (!sessions) {
        perror("malloc TLS handshake sessions");
        ret = -1;
        goto exit_free_sessions;
    }
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            /* Skip our own rank. */
            continue;
        }

        /* Initialize SSL. */
        ret =
            init_handshake_session(&handshake_sessions[i], i, &sessions[i],
                    &cert, &privkey, entropy);
        if (ret) {
            handle_error_string("Failed to initialize TLS handshake session");
            for (int j = 0; j < i; j++) {
                free_handshake_session(&handshake_sessions[j]);
            }
            free(sessions);
            goto exit_free_sessions;
        }
    }

    /* Handshake with all nodes. */
    for (int i = 0; i < world_size; i++) {
        for (int j = i + 1; j < world_size; j++) {
            if (i != world_rank && j != world_rank) {
                continue;
            }

            /* Do handshake. */
            ret = mbedtls_ssl_handshake(&handshake_sessions[i == world_rank ? j : i].ssl);
            if (ret) {
                handle_mbedtls_error(ret, "mbedtls_ssl_handshake");
                goto exit_free_handshake_sessions;
            }
        }
    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result = ocall_mpi_barrier();
    if (result != OE_OK) {
        handle_oe_error(result, "ocall_mpi_barrier");
    }
#else
    ocall_mpi_barrier();
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */

    ret = 0;

exit_free_handshake_sessions:
    for (int i = 0; i < world_size; i++) {
        if (i == world_rank) {
            continue;
        }
        free_handshake_session(&handshake_sessions[i]);
    }
    free(handshake_sessions);
exit_free_sessions:
    if (ret) {
        /* Only free if function failed. */
        free(sessions);
    }
exit_free_keys:
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&privkey);
exit:
    return ret;
}

void mpi_tls_free(void) {
    free(sessions);
    mbedtls_x509_crt_free(&cert);
    mbedtls_pk_free(&privkey);
}

int mpi_tls_send_bytes(const void *buf, size_t count, int dest, int tag) {
    struct mpi_tls_session *session = &sessions[dest];
    int ret;

    /* Allocate send buffer. */
    size_t out_buf_len = IV_LEN + TAG_LEN + count;
    unsigned char *out_buf = malloc(out_buf_len);
    if (!out_buf) {
        perror("malloc out_buf");
        ret = -1;
        goto exit;
    }

    /* Generate IV in the first IV_LEN bytes of the buffer. */
    ret = rand_read(out_buf, IV_LEN);
    if (ret) {
        handle_error_string("Error generating encrypted MPI IV");
        goto exit_free_out_buf;
    }

    /* Encrypt. Tag goes in the TAG_LEN bytes after the IV. Ciphertext goes in
     * the remaining bytes after the IV and tag. */
    // TODO Incorporate message tag in ciphertext for authentication.
    ret =
        aad_encrypt(session->send_key, buf, count, NULL, 0, out_buf,
                out_buf + IV_LEN + TAG_LEN, out_buf + IV_LEN);
    if (ret) {
        handle_error_string("Error encrypting encrypted MPI data");
        goto exit_free_out_buf;
    }

    /* Send buffer over MPI. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_send_bytes(&ret, out_buf, out_buf_len, dest, tag);
    if (result != OE_OK) {
        handle_oe_error(ret, "ocall_mpi_send_bytes");
        goto exit_free_out_buf;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret = ocall_mpi_send_bytes(out_buf, out_buf_len, dest, tag);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error sending encrypted MPI data");
        goto exit_free_out_buf;
    }

    __atomic_add_fetch(&mpi_tls_bytes_sent, out_buf_len, __ATOMIC_RELAXED);

exit_free_out_buf:
    free(out_buf);
exit:
    return ret;
}

int mpi_tls_recv_bytes(void *buf, size_t count, int src, int tag,
        mpi_tls_status_t *status) {
    int ret;

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

    /* Allocate receive buffer. */
    size_t in_buf_len = IV_LEN + TAG_LEN + count;
    unsigned char *in_buf = malloc(in_buf_len);
    if (!in_buf) {
        perror("malloc in_buf");
        ret = -1;
        goto exit;
    }

    /* Receive buffer over MPI. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_recv_bytes(&ret, in_buf, in_buf_len, src, tag, status);
    if (result != OE_OK) {
        handle_oe_error(ret, "ocall_mpi_recv_bytes");
        goto exit_free_in_buf;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret = ocall_mpi_recv_bytes(in_buf, in_buf_len, src, tag, status);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error receiving encrypted MPI data");
        goto exit_free_in_buf;
    }

    /* Decrypt. */
    if (status->count < IV_LEN + TAG_LEN) {
        handle_error_string(
                "Received encrypted MPI data is shorter than IV + tag length");
        goto exit_free_in_buf;
    }
    ret =
        aad_decrypt(sessions[status->source].recv_key,
            in_buf + IV_LEN + TAG_LEN, status->count - IV_LEN - TAG_LEN, NULL,
            0, in_buf, in_buf + IV_LEN, buf);
    if (ret) {
        handle_error_string("Error decrypting encrypted MPI data");
        goto exit_free_in_buf;
    }
    status->count -= IV_LEN + TAG_LEN;

exit_free_in_buf:
    free(in_buf);
exit:
    return ret;
}

int mpi_tls_isend_bytes(const void *buf_, size_t count, int dest, int tag,
        mpi_tls_request_t *request) {
    struct mpi_tls_session *session = &sessions[dest];
    const unsigned char *buf = buf_;
    int ret;

    /* Allocate send buffer. */
    request->enc_buf_len = IV_LEN + TAG_LEN + count;
    request->enc_buf = malloc(request->enc_buf_len);
    if (!request->enc_buf) {
        perror("malloc request->enc_buf");
        ret = -1;
        goto exit;
    }

    /* Generate IV in the first IV_LEN bytes of the buffer. */
    ret = rand_read(request->enc_buf, IV_LEN);
    if (ret) {
        handle_error_string("Error generating encrypted MPI IV");
        goto exit_free_enc_buf;
    }

    /* Encrypt. Tag goes in the TAG_LEN bytes after the IV. Ciphertext goes in
     * the remaining bytes after the IV and tag. */
    // TODO Incorporate message tag in ciphertext for authentication.
    ret =
        aad_encrypt(session->send_key, buf, count, NULL, 0, request->enc_buf,
                request->enc_buf + IV_LEN + TAG_LEN, request->enc_buf + IV_LEN);
    if (ret) {
        handle_error_string("Error encrypting encrypted MPI data");
        goto exit_free_enc_buf;
    }

    request->type = MPI_TLS_SEND;

    /* Send buffer over MPI. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_isend_bytes(&ret, request->enc_buf, request->enc_buf_len,
                dest, tag, &request->mpi_request);
    if (result != OE_OK) {
        handle_oe_error(ret, "ocall_mpi_isend_bytes");
        goto exit_free_enc_buf;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret =
        ocall_mpi_isend_bytes(request->enc_buf, request->enc_buf_len, dest, tag,
                &request->mpi_request);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error posting send for encrypted MPI data");
        goto exit_free_enc_buf;
    }

    __atomic_add_fetch(&mpi_tls_bytes_sent, request->enc_buf_len,
            __ATOMIC_RELAXED);

exit:
    return ret;

exit_free_enc_buf:
    free(request->enc_buf);
    return ret;
}

int mpi_tls_irecv_bytes(void *buf, size_t count, int src, int tag,
        mpi_tls_request_t *request) {
    int ret;

    if (src == MPI_TLS_ANY_SOURCE) {
        src = OCALL_MPI_ANY_SOURCE;
    }
    if (tag == MPI_TLS_ANY_TAG) {
        tag = OCALL_MPI_ANY_TAG;
    }

    /* Allocate receive buffer. */
    request->enc_buf_len = IV_LEN + TAG_LEN + count;
    request->enc_buf = malloc(request->enc_buf_len);
    if (!request->enc_buf) {
        perror("malloc request->enc_buf");
        ret = -1;
        goto exit;
    }

    /* Receive buffer over MPI. */
#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_irecv_bytes(&ret, request->enc_buf_len, src, tag,
                &request->mpi_request);
    if (result != OE_OK) {
        handle_oe_error(ret, "ocall_mpi_recv_bytes");
        goto exit_free_enc_buf;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret =
        ocall_mpi_irecv_bytes(request->enc_buf_len, src, tag,
                &request->mpi_request);
#endif /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    if (ret) {
        handle_error_string("Error posting receive for encrypted MPI data");
        goto exit_free_enc_buf;
    }

    request->buf = buf;
    request->type = MPI_TLS_RECV;
    request->count = count;

exit:
    return ret;

exit_free_enc_buf:
    free(request->enc_buf);
    return ret;
}

int mpi_tls_wait(mpi_tls_request_t *request, mpi_tls_status_t *status) {
    int ret;

    mpi_tls_status_t ignored_status;
    if (status == MPI_TLS_STATUS_IGNORE) {
        status = &ignored_status;
    }

    unsigned char *wait_buf;
    size_t wait_buf_len;
    switch (request->type) {
    case MPI_TLS_NULL:
    case MPI_TLS_SEND:
        wait_buf = NULL;
        wait_buf_len = 0;
        break;
    case MPI_TLS_RECV:
        wait_buf = request->enc_buf;
        wait_buf_len = request->enc_buf_len;
        break;
    default:
        handle_error_string("Invalid request type");
        ret = -1;
        goto exit;
    }

    ocall_mpi_request_t mpi_request;
    if (request->type == MPI_TLS_NULL) {
        mpi_request = OCALL_MPI_REQUEST_NULL;
    } else {
        mpi_request = request->mpi_request;
    }

#ifndef DISTRIBUTED_SGX_SORT_HOSTONLY
    oe_result_t result =
        ocall_mpi_wait(&ret, wait_buf, wait_buf_len, &mpi_request, status);
    if (result != OE_OK) {
        handle_oe_error(result, "ocall_mpi_wait");
        ret = result;
        goto exit;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret = ocall_mpi_wait(wait_buf, wait_buf_len, &mpi_request, status);
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
        /* Decrypt. */
        if (status->count < IV_LEN + TAG_LEN) {
            handle_error_string(
                    "Received encrypted MPI data is shorter than IV + tag length");
            goto exit;
        }
        ret =
            aad_decrypt(sessions[status->source].recv_key,
                request->enc_buf + IV_LEN + TAG_LEN,
                status->count - IV_LEN - TAG_LEN, NULL, 0, request->enc_buf,
                request->enc_buf + IV_LEN, request->buf);
        if (ret) {
            handle_error_string("Error decrypting encrypted MPI data");
            goto exit;
        }
        status->count -= IV_LEN + TAG_LEN;

        break;
    }
    }

exit:
    free(request->enc_buf);
    return ret;
}

int mpi_tls_waitany(size_t count, mpi_tls_request_t *requests, size_t *index,
        mpi_tls_status_t *status) {
    int ret;

    mpi_tls_status_t ignored_status;
    if (status == MPI_TLS_STATUS_IGNORE) {
        status = &ignored_status;
    }

    unsigned char *wait_buf = NULL;
    size_t wait_buf_len = 0;
    for (size_t i = 0; i < count; i++) {
        switch (requests[i].type) {
        case MPI_TLS_NULL:
        case MPI_TLS_SEND:
            break;
        case MPI_TLS_RECV:
            if (requests[i].enc_buf_len > wait_buf_len) {
                wait_buf = requests[i].enc_buf;
                wait_buf_len = requests[i].enc_buf_len;
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
        ocall_mpi_waitany(&ret, wait_buf, wait_buf_len, count, mpi_requests,
                index, status);
    if (result != OE_OK) {
        handle_oe_error(result, "ocall_mpi_waitany");
        ret = result;
        goto exit;
    }
#else /* DISTRIBUTED_SGX_SORT_HOSTONLY */
    ret =
        ocall_mpi_waitany(wait_buf, wait_buf_len, count, mpi_requests, index,
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
        /* Decrypt. */
        if (status->count < IV_LEN + TAG_LEN) {
            handle_error_string(
                    "Received encrypted MPI data is shorter than IV + tag length");
            goto exit;
        }
        ret =
            aad_decrypt(sessions[status->source].recv_key,
                wait_buf + IV_LEN + TAG_LEN, status->count - IV_LEN - TAG_LEN,
                NULL, 0, wait_buf, wait_buf + IV_LEN, requests[*index].buf);
        if (ret) {
            handle_error_string("Error decrypting encrypted MPI data");
            goto exit;
        }
        status->count -= IV_LEN + TAG_LEN;

        break;
    }
    }

exit:
    free(requests[*index].enc_buf);
    return ret;
}
