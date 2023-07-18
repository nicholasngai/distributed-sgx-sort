#include "enclave/ojoin.h"
#include <stddef.h>
#include "common/elem_t.h"
#include "enclave/bucket.h"

int ojoin_init(void) {
    int ret;

    ret = bucket_init();
    if (ret) {
        goto exit;
    }

exit:
    return ret;
}

void ojoin_free(void) {
    bucket_free();
}

int ojoin(elem_t *arr, size_t length, size_t num_threads) {
    (void) arr;
    (void) length;
    (void) num_threads;
    return 0;
}
