#include "mpi_tls.h"
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openenclave/enclave.h>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/evidence.h>
#include "common/defs.h"
#include "parallel_t.h"

#define BUFFER_SIZE 4096

#ifdef OE_SIMULATION
static unsigned char SIM_PRIVKEY[302] = {
    0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x43, 0x20, 0x50, 0x41,
    0x52, 0x41, 0x4d, 0x45, 0x54, 0x45, 0x52, 0x53, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x42, 0x67,
    0x67, 0x71, 0x68, 0x6b, 0x6a, 0x4f, 0x50, 0x51, 0x4d, 0x42, 0x42, 0x77, 0x3d, 0x3d, 0x0a, 0x2d,
    0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x45, 0x43, 0x20, 0x50, 0x41, 0x52, 0x41, 0x4d,
    0x45, 0x54, 0x45, 0x52, 0x53, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d,
    0x42, 0x45, 0x47, 0x49, 0x4e, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52, 0x49, 0x56, 0x41, 0x54, 0x45,
    0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a, 0x4d, 0x48, 0x63, 0x43, 0x41, 0x51,
    0x45, 0x45, 0x49, 0x4a, 0x77, 0x46, 0x4e, 0x49, 0x57, 0x6c, 0x4f, 0x7a, 0x57, 0x43, 0x2b, 0x65,
    0x61, 0x74, 0x4c, 0x6e, 0x4a, 0x35, 0x4f, 0x64, 0x77, 0x49, 0x2f, 0x42, 0x35, 0x34, 0x79, 0x7a,
    0x7a, 0x35, 0x53, 0x34, 0x55, 0x76, 0x5a, 0x6a, 0x53, 0x68, 0x2b, 0x75, 0x61, 0x45, 0x6f, 0x41,
    0x6f, 0x47, 0x43, 0x43, 0x71, 0x47, 0x53, 0x4d, 0x34, 0x39, 0x0a, 0x41, 0x77, 0x45, 0x48, 0x6f,
    0x55, 0x51, 0x44, 0x51, 0x67, 0x41, 0x45, 0x2b, 0x65, 0x4a, 0x78, 0x33, 0x42, 0x35, 0x59, 0x68,
    0x4c, 0x48, 0x47, 0x56, 0x61, 0x6e, 0x63, 0x42, 0x6d, 0x7a, 0x4d, 0x47, 0x59, 0x30, 0x52, 0x5a,
    0x72, 0x6b, 0x2b, 0x39, 0x72, 0x33, 0x72, 0x37, 0x41, 0x6a, 0x7a, 0x36, 0x56, 0x74, 0x75, 0x34,
    0x52, 0x51, 0x65, 0x42, 0x66, 0x67, 0x6e, 0x56, 0x6a, 0x2f, 0x45, 0x0a, 0x35, 0x75, 0x43, 0x47,
    0x7a, 0x55, 0x78, 0x55, 0x49, 0x5a, 0x38, 0x64, 0x2f, 0x47, 0x6d, 0x47, 0x4a, 0x4d, 0x76, 0x46,
    0x61, 0x42, 0x4d, 0x49, 0x66, 0x4a, 0x46, 0x65, 0x38, 0x65, 0x36, 0x75, 0x65, 0x77, 0x3d, 0x3d,
    0x0a, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x45, 0x4e, 0x44, 0x20, 0x45, 0x43, 0x20, 0x50, 0x52, 0x49,
    0x56, 0x41, 0x54, 0x45, 0x20, 0x4b, 0x45, 0x59, 0x2d, 0x2d, 0x2d, 0x2d, 0x2d, 0x0a,
};

static unsigned char SIM_CERT[639] = {
    0x30, 0x82, 0x02, 0x7b, 0x30, 0x82, 0x02, 0x21, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x14, 0x3e,
    0xc1, 0xcb, 0x89, 0x7a, 0x85, 0x58, 0x04, 0xb9, 0x43, 0x67, 0x3b, 0xfd, 0xb6, 0xa3, 0x0c, 0x06,
    0x8c, 0x95, 0xd9, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30,
    0x81, 0x91, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
    0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f,
    0x72, 0x6e, 0x69, 0x61, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0c, 0x08, 0x42,
    0x65, 0x72, 0x6b, 0x65, 0x6c, 0x65, 0x79, 0x31, 0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04, 0x0a,
    0x0c, 0x22, 0x55, 0x6e, 0x69, 0x76, 0x65, 0x72, 0x73, 0x69, 0x74, 0x79, 0x20, 0x6f, 0x66, 0x20,
    0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x2c, 0x20, 0x42, 0x65, 0x72, 0x6b,
    0x65, 0x6c, 0x65, 0x79, 0x31, 0x2d, 0x30, 0x2b, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x24, 0x44,
    0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x64, 0x20, 0x53, 0x47, 0x58, 0x20, 0x53,
    0x6f, 0x72, 0x74, 0x20, 0x53, 0x69, 0x6d, 0x75, 0x6c, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4d,
    0x6f, 0x64, 0x65, 0x30, 0x20, 0x17, 0x0d, 0x32, 0x31, 0x30, 0x34, 0x31, 0x33, 0x30, 0x30, 0x32,
    0x35, 0x32, 0x35, 0x5a, 0x18, 0x0f, 0x32, 0x31, 0x32, 0x31, 0x30, 0x33, 0x32, 0x30, 0x30, 0x30,
    0x32, 0x35, 0x32, 0x35, 0x5a, 0x30, 0x81, 0x91, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
    0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0c, 0x0a,
    0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x11, 0x30, 0x0f, 0x06, 0x03,
    0x55, 0x04, 0x07, 0x0c, 0x08, 0x42, 0x65, 0x72, 0x6b, 0x65, 0x6c, 0x65, 0x79, 0x31, 0x2b, 0x30,
    0x29, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x22, 0x55, 0x6e, 0x69, 0x76, 0x65, 0x72, 0x73, 0x69,
    0x74, 0x79, 0x20, 0x6f, 0x66, 0x20, 0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61,
    0x2c, 0x20, 0x42, 0x65, 0x72, 0x6b, 0x65, 0x6c, 0x65, 0x79, 0x31, 0x2d, 0x30, 0x2b, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x24, 0x44, 0x69, 0x73, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x64,
    0x20, 0x53, 0x47, 0x58, 0x20, 0x53, 0x6f, 0x72, 0x74, 0x20, 0x53, 0x69, 0x6d, 0x75, 0x6c, 0x61,
    0x74, 0x69, 0x6f, 0x6e, 0x20, 0x4d, 0x6f, 0x64, 0x65, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    0x03, 0x42, 0x00, 0x04, 0xf9, 0xe2, 0x71, 0xdc, 0x1e, 0x58, 0x84, 0xb1, 0xc6, 0x55, 0xa9, 0xdc,
    0x06, 0x6c, 0xcc, 0x19, 0x8d, 0x11, 0x66, 0xb9, 0x3e, 0xf6, 0xbd, 0xeb, 0xec, 0x08, 0xf3, 0xe9,
    0x5b, 0x6e, 0xe1, 0x14, 0x1e, 0x05, 0xf8, 0x27, 0x56, 0x3f, 0xc4, 0xe6, 0xe0, 0x86, 0xcd, 0x4c,
    0x54, 0x21, 0x9f, 0x1d, 0xfc, 0x69, 0x86, 0x24, 0xcb, 0xc5, 0x68, 0x13, 0x08, 0x7c, 0x91, 0x5e,
    0xf1, 0xee, 0xae, 0x7b, 0xa3, 0x53, 0x30, 0x51, 0x30, 0x1d, 0x06, 0x03, 0x55, 0x1d, 0x0e, 0x04,
    0x16, 0x04, 0x14, 0x8d, 0x1f, 0x74, 0xaf, 0x7d, 0x3f, 0x5e, 0xa0, 0x60, 0xfb, 0x3a, 0x02, 0xdb,
    0x91, 0x74, 0x6e, 0xcd, 0xa8, 0x49, 0xe8, 0x30, 0x1f, 0x06, 0x03, 0x55, 0x1d, 0x23, 0x04, 0x18,
    0x30, 0x16, 0x80, 0x14, 0x8d, 0x1f, 0x74, 0xaf, 0x7d, 0x3f, 0x5e, 0xa0, 0x60, 0xfb, 0x3a, 0x02,
    0xdb, 0x91, 0x74, 0x6e, 0xcd, 0xa8, 0x49, 0xe8, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01,
    0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01, 0xff, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48,
    0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x21, 0x00, 0xa9, 0xb2, 0x80,
    0xf3, 0xfb, 0xa5, 0x40, 0x74, 0xbd, 0x38, 0x05, 0x6c, 0x6c, 0x79, 0x97, 0x4b, 0x10, 0xd9, 0x21,
    0xdd, 0x3b, 0xb9, 0x0f, 0xf0, 0x09, 0x71, 0xa8, 0x61, 0x6a, 0x93, 0x0f, 0xd3, 0x02, 0x20, 0x3b,
    0x30, 0x34, 0xd3, 0x46, 0x75, 0x02, 0x48, 0xfc, 0x97, 0xf1, 0xec, 0x2b, 0x92, 0x09, 0x2e, 0x30,
    0xb5, 0x25, 0x33, 0x56, 0xc3, 0x32, 0xd1, 0xc6, 0x3a, 0x92, 0xdd, 0x5d, 0xb2, 0x75, 0x51,
};
#endif /* OE_SIMULATION */

struct mpi_tls_session {
    SSL *ssl;
    BIO *rbio;
    BIO *wbio;
};

static size_t world_rank;
static size_t world_size;
static unsigned char *buffer;
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

static int load_certificate_and_key(X509 **cert, EVP_PKEY **privkey) {
    /* Generate public/private key pair and certificate buffers. */
    unsigned char *privkey_buf;
    unsigned char *cert_buf;
    size_t cert_buf_size;
    int ret = -1;

#ifndef OE_SIMULATION
    unsigned char *pubkey_buf;
    size_t pubkey_buf_size;
    size_t privkey_buf_size;
    oe_result_t result;

    oe_asymmetric_key_params_t key_params;
    key_params.type = OE_ASYMMETRIC_KEY_EC_SECP256P1;
    key_params.format = OE_ASYMMETRIC_KEY_PEM;
    key_params.user_data = NULL;
    key_params.user_data_size = 0;
    result = oe_get_public_key_by_policy(OE_SEAL_POLICY_UNIQUE, &key_params,
            &pubkey_buf, &pubkey_buf_size, NULL, 0);
    if (result != OE_OK) {
        fprintf(stderr, "oe_get_public_key_by_policy: %s\n",
                oe_result_str(result));
        goto exit;
    }
    result = oe_get_private_key_by_policy(OE_SEAL_POLICY_UNIQUE, &key_params,
            &privkey_buf, &privkey_buf_size, NULL, 0);
    if (result != OE_OK) {
        fprintf(stderr, "oe_get_private_key_by_policy: %s\n",
                oe_result_str(result));
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
        fprintf(stderr, "oe_get_attestation_cert_buf_with_evidence_v2: %s\n",
                oe_result_str(result));
        goto exit_free_privkey_buf;
    }
#else /* OE_SIMULATION */
    privkey_buf = SIM_PRIVKEY;
    cert_buf = SIM_CERT;
    cert_buf_size = sizeof(SIM_CERT);
#endif
    BIO *privkey_buf_bio = BIO_new_mem_buf(privkey_buf, -1);
    if (!privkey_buf_bio) {
        fprintf(stderr, "Failed to allocate BIO for private key\n");
        goto exit_free_cert_buf;
    }
    *privkey = PEM_read_bio_PrivateKey(privkey_buf_bio, NULL, NULL, NULL);
    if (!*privkey) {
        fprintf(stderr, "Failed to parse private key from PEM\n");
        goto exit_free_privkey_bio;
    }
    const unsigned char *cert_buf_ptr = cert_buf;
    *cert = d2i_X509(NULL, &cert_buf_ptr, cert_buf_size);
    if (!*cert) {
        EVP_PKEY_free(*privkey);
        fprintf(stderr, "Failed to parse X.509 certificate from DER\n");
        goto exit_free_privkey_bio;
    }

    ret = 0;

exit_free_privkey_bio:
    BIO_free(privkey_buf_bio);
exit_free_cert_buf:
#ifndef OE_SIMULATION
    oe_free_attestation_certificate(cert_buf);
exit_free_privkey_buf:
    oe_free_key(privkey_buf, privkey_buf_size, NULL, 0);
exit_free_pubkey_buf:
    oe_free_key(pubkey_buf, pubkey_buf_size, NULL, 0);
exit:
#endif /* OE_SIMULATION */
    return ret;
}

static int verify_callback(int preverify_ok UNUSED,
        X509_STORE_CTX *ctx UNUSED) {
    // TODO Implement actual SGX attestation verification.
    return 1;
}

int mpi_tls_init(size_t world_rank_, size_t world_size_) {
    oe_result_t result;

    world_rank = world_rank_;
    world_size = world_size_;

    /* Initialize buffer. */
    buffer = malloc(BUFFER_SIZE);
    if (!buffer) {
        perror("malloc buffer");
        goto exit;
    }

    /* Load certificate and private key. */
    X509 *cert;
    EVP_PKEY *privkey;
    if (load_certificate_and_key(&cert, &privkey)) {
        fprintf(stderr, "Failed to load certificate and private key\n");
        goto exit_free_buffer;
    }

    /* Initialize global context. */
    // TODO Think about downgrade attacks. All clients will be on the same
    // version, anyway.
    ctx = SSL_CTX_new(TLS_method());
    if (!ctx) {
        fprintf(stderr, "Failed to allocate SSL context\n");
        X509_free(cert);
        EVP_PKEY_free(privkey);
        goto exit_free_buffer;
    }
    SSL_CTX_use_certificate(ctx, cert);
    SSL_CTX_use_PrivateKey(ctx, privkey);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    /* Initialize TLS sessions. */
    sessions = malloc(world_size * sizeof(*sessions));
    if (!sessions) {
        perror("malloc TLS sessions");
        goto exit_free_ctx;
    }
    for (size_t i = 0; i < world_size; i++) {
        if (i == world_rank) {
            /* Skip our own rank and zero out all memory. */
            memset(&sessions[i], '\0', sizeof(sessions[i]));
            continue;
        }

        int ret = init_session(&sessions[i]);
        if (ret) {
            fprintf(stderr, "Failed to initialize TLS session structures\n");
            for (size_t j = 0; j < i; j++) {
                free_session(&sessions[j]);
            }
            free(sessions);
            goto exit_free_ctx;
        }

        /* We act as clients to lower ranks and servers to higher ranks. */
        if (i > world_rank) {
            /* Server. */
            SSL_set_accept_state(sessions[i].ssl);
        } else {
            /* Client. */
            SSL_set_connect_state(sessions[i].ssl);
        }
    }

    /* Handshake with all nodes. Reepatedly loop until all handshakes are
     * finished. */
    bool all_init_finished;
    do {
        all_init_finished = true;
        for (size_t i = 0; i < world_size; i++) {
            /* Skip our own rank. */
            if (i == world_rank) {
                continue;
            }

            /* Skip if init finished. */
            if (SSL_is_init_finished(sessions[i].ssl)) {
                continue;
            }

            /* Init not finished. */

            int ret;

            all_init_finished = false;

            /* Do handshake. */
            ret = SSL_do_handshake(sessions[i].ssl);
            if (ret < 0) {
                int err = SSL_get_error(sessions[i].ssl, ret);
                if (err != SSL_ERROR_NONE && err != SSL_ERROR_WANT_READ
                        && err != SSL_ERROR_WANT_WRITE) {
                    fprintf(stderr, "SSL_do_handshake: %d\n", err);
                    goto exit_free_sessions;
                }
            }

            /* Send bytes. */
            int bytes_to_send;
            do {
               bytes_to_send = BIO_read(sessions[i].wbio, buffer, BUFFER_SIZE);
               if (bytes_to_send > 0) {
                   result = ocall_mpi_send_bytes(&ret, buffer, bytes_to_send, i,
                           0);
                   if (result != OE_OK) {
                       fprintf(stderr, "ocall_mpi_send_bytes: %s\n",
                               oe_result_str(result));
                       goto exit_free_sessions;
                   }
                   if (ret) {
                       fprintf(stderr, "Failed to send TLS handshake bytes\n");
                       goto exit_free_sessions;
                   }
               }
            } while (bytes_to_send == BUFFER_SIZE);

            /* Receive bytes. */
            int bytes_received;
            do {
                result = ocall_mpi_try_recv_bytes(&bytes_received, buffer,
                        BUFFER_SIZE, i, 0);
                if (result != OE_OK) {
                    fprintf(stderr, "ocall_mpi_try_recv_bytes: %s\n",
                            oe_result_str(result));
                    goto exit_free_sessions;
                }
                if (bytes_received < 0) {
                    fprintf(stderr, "Failed to recieve TLS handshake bytes\n");
                    goto exit_free_sessions;
                }
                BIO_write(sessions[i].rbio, buffer, bytes_received);
            } while (bytes_received == BUFFER_SIZE);
        }
    } while (!all_init_finished);

    ocall_mpi_barrier();

    /* Read all remaining bytes and write them to the BIO. */
    for (size_t i = 0; i < world_size; i++) {
        /* Skip our own rank. */
        if (i == world_rank) {
            continue;
        }

        int bytes_received;
        do {
            result = ocall_mpi_try_recv_bytes(&bytes_received, buffer,
                    BUFFER_SIZE, i, 0);
            if (result != OE_OK) {
                fprintf(stderr, "ocall_mpi_try_recv_bytes: %s\n",
                        oe_result_str(result));
                goto exit_free_sessions;
            }
            if (bytes_received < 0) {
                fprintf(stderr, "Failed to receive TLS handshake tail bytes\n");
                goto exit_free_sessions;
            }
            BIO_write(sessions[i].rbio, buffer, bytes_received);
        } while (bytes_received == BUFFER_SIZE);
    }

    ocall_mpi_barrier();

    return 0;

exit_free_sessions:
    for (size_t i = 0; i < world_size; i++) {
        free_session(&sessions[i]);
    }
    free(sessions);
exit_free_ctx:
    SSL_CTX_free(ctx);
    /* X509 and EVP_PKEY freed with SSL_CTX_free. */
exit_free_buffer:
    free(buffer);
exit:
    return -1;
}

void mpi_tls_free(void) {
    for (size_t i = 0; i < world_size; i++) {
        free_session(&sessions[i]);
    }
    free(sessions);
    SSL_CTX_free(ctx);
    free(buffer);
}

int mpi_tls_send_bytes(const unsigned char *buf, size_t count, int dest,
        int tag) {
    oe_result_t result;
    int ret = -1;

    SSL_write(sessions[dest].ssl, buf, count);

    int bytes_to_send;
    do {
        bytes_to_send = BIO_read(sessions[dest].wbio, buffer, BUFFER_SIZE);
        if (bytes_to_send > 0) {
            result = ocall_mpi_send_bytes(&ret, buffer, bytes_to_send, dest, tag);
            if (result != OE_OK || ret) {
                fprintf(stderr, "ocall_mpi_send_bytes: %s\n",
                        oe_result_str(result));
            }
        }
    } while (bytes_to_send == BUFFER_SIZE);

    return ret;
}

int mpi_tls_recv_bytes(unsigned char *buf, size_t count, int src, int tag) {
    oe_result_t result;
    int ret = -1;

    size_t bytes_read = 0;
    while (bytes_read < count) {
        int bytes_received;
        result = ocall_mpi_try_recv_bytes(&bytes_received, buffer,
                BUFFER_SIZE, src, tag);
        if (result != OE_OK) {
            fprintf(stderr, "ocall_mpi_try_recv_bytes: %s\n",
                    oe_result_str(result));
            goto exit;
        }
        if (bytes_received < 0) {
            fprintf(stderr, "Error receiving TLS bytes\n");
            goto exit;
        }
        BIO_write(sessions[src].rbio, buffer, bytes_received);
        int read = SSL_read(sessions[src].ssl, buf + bytes_read,
                count - bytes_read);
        if (read <= 0) {
            int err = SSL_get_error(sessions[src].ssl, read);
            if (err != SSL_ERROR_WANT_READ) {
                fprintf(stderr, "SSL_read: %d\n", err);
                goto exit;
            }
        }
        if (read > 0) {
            bytes_read += read;
        }
    }

    ret = 0;

exit:
    return ret;
}
