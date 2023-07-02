#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <openenclave/host.h>
#include "host/membenchmark_u.h"

int main(int argc, char **argv) {
    int ret;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <enclave image>\n", argv[0]);
        ret = 1;
        goto exit;
    }

    const char *enclave_path = argv[1];

    oe_result_t result;

    /* Allocate enclave. */
    oe_enclave_t *enclave;
    result = oe_create_membenchmark_enclave(
            enclave_path,
            OE_ENCLAVE_TYPE_AUTO,
            0
#ifdef OE_DEBUG
                | OE_ENCLAVE_FLAG_DEBUG
#endif
#ifdef OE_SIMULATION
                | OE_ENCLAVE_FLAG_SIMULATE
#endif
                ,
            NULL,
            0,
            &enclave);
    if (result != OE_OK) {
        fprintf(stderr, "oe_create_membenchmark_enclave: %s\n",
                oe_result_str(result));
        ret = 1;
        goto exit;
    }

    ret = 0;

    /* Cleanup. */
    result = oe_terminate_enclave(enclave);
    if (result != OE_OK) {
        fprintf(stderr, "oe_terminate_enclave: %s\n", oe_result_str(result));
    }
exit:
    return ret;
}
