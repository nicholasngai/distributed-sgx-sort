#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "enclave/membenchmark_t.h"

static char *_arr;
static size_t _len;
static size_t _num_threads;
static volatile size_t threads_finished;
static volatile bool ready;

static void access_array(char *arr, size_t len, size_t num_threads,
        size_t thread_idx) {
    for (size_t i = len * thread_idx / num_threads;
            i < len * (thread_idx + 1) / num_threads; i++) {
        arr[i] += 1;
    }
}

void ecall_thread_work(size_t thread_idx) {
    while (!__atomic_load_n(&ready, __ATOMIC_ACQUIRE)) {}
    access_array(_arr, _len, _num_threads, thread_idx);
    __atomic_fetch_add(&threads_finished, 1, __ATOMIC_RELEASE);
}

int ecall_benchmark(size_t alloc_size, size_t num_threads) {
    int ret;

    char *arr = malloc(alloc_size);
    if (!arr) {
        ret = -1;
        perror("malloc arr");
        goto exit;
    }

    _arr = arr;
    _len = alloc_size;
    _num_threads = num_threads;
    threads_finished = 0;
    __atomic_store_n(&ready, true, __ATOMIC_RELEASE);

    ecall_thread_work(0);

    while (__atomic_load_n(&threads_finished, __ATOMIC_ACQUIRE) < num_threads) {}
    __atomic_store_n(&ready, false, __ATOMIC_RELEASE);

    ret = 0;

    free(arr);
exit:
    return ret;
}
