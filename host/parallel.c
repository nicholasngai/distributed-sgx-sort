#include <stdio.h>
#include <openenclave/host.h>
#include "parallel_u.h"

int main(int argc, char *argv[]) {
    oe_enclave_t *enclave;
    oe_result_t result;
    int ret = 0;

    if (argc < 2) {
        printf("usage: %s enclave_image\n", argv[0]);
    }

    result = oe_create_parallel_enclave(
            argv[1],
            OE_ENCLAVE_TYPE_AUTO,
            OE_ENCLAVE_FLAG_DEBUG | OE_ENCLAVE_FLAG_SIMULATE,
            NULL,
            0,
            &enclave);

    if (result != OE_OK) {
        printf("Enclave creation failed: %s\n", oe_result_str(result));
        ret = result;
        goto exit;
    }

    ecall_main(enclave, &ret);

    if (ret) {
        printf("Enclave exited with return code %d\n", ret);
    }

    oe_terminate_enclave(enclave);
exit:
    return ret;
}
