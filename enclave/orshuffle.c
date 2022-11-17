#include "enclave/orshuffle.h"
#include <stddef.h>
#include "enclave/parallel_enc.h"
#include "enclave/nonoblivious.h"

int orshuffle_init(void) {
    return 0;
}

void orshuffle_free(void) {}

int orshuffle_sort(void *arr, size_t length, size_t num_threads) {
    size_t local_start = length * world_rank / world_size;
    size_t local_length = length * (world_rank + 1) / world_size - local_start;
    int ret;

    ret = nonoblivious_sort(arr, length, local_length, local_start);
    if (ret) {
        goto exit;
    }

exit:
    return ret;
}
