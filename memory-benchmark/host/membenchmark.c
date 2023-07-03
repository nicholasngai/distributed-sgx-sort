#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <openenclave/host.h>
#include "host/membenchmark_u.h"

struct do_thread_work_args {
    oe_enclave_t *enclave;
    size_t thread_idx;
};

void *do_thread_work(void *args_) {
    struct do_thread_work_args *args = args_;
    oe_enclave_t *enclave = args->enclave;
    size_t thread_idx = args->thread_idx;
    void *ret;

    oe_result_t result = ecall_thread_work(enclave, thread_idx);
    if (result != OE_OK) {
        fprintf(stderr, "ecall_thread_work: %s\n", oe_result_str(result));
        ret = (void *) -1;
        goto exit;
    }

    ret = NULL;

exit:
    return ret;
}

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

    /* Benchmark. */
    for (size_t size = 1lu << 20; size <= 1lu << 30; size *= 4) {
        for (size_t num_threads = 1; num_threads <= 8; num_threads *= 2) {
            /* Spawn threads. */
            pthread_t threads[num_threads];
            struct do_thread_work_args args[num_threads];
            for (size_t i = 1; i < num_threads; i++) {
                args[i] = (struct do_thread_work_args) {
                    .enclave = enclave,
                    .thread_idx = i,
                };
                if (pthread_create(&threads[i], NULL, do_thread_work,
                            &args[i])) {
                    perror("pthread_create");
                    ret = 1;
                    goto exit_terminate_enclave;
                }
            }

            /* Start timer. */
            clock_t start = clock();

            /* Do benchmark. */
            result = ecall_benchmark(enclave, &ret, size, num_threads);
            if (result != OE_OK) {
                fprintf(stderr, "ecall_benchmark: %s\n", oe_result_str(result));
                ret = 1;
                goto exit_terminate_enclave;
            }
            if (ret) {
                fprintf(stderr, "ecall_benchmark: %d\n", ret);
                goto exit_terminate_enclave;
            }

            /* End timer and print time. */
            clock_t end = clock();
            printf("size = %zu; num_threads = %zu; time = %f\n", size,
                    num_threads, (double) (end - start) / CLOCKS_PER_SEC);

            /* Join threads. */
            for (size_t i = 1; i < num_threads; i++) {
                void *thread_ret;
                if (pthread_join(threads[i], &thread_ret)) {
                    perror("pthread_join");
                    ret = 1;
                    goto exit_terminate_enclave;
                }
                if (thread_ret) {
                    fprintf(stderr, "Thread returned %zd\n",
                            (intptr_t) thread_ret);
                    ret = 1;
                    goto exit_terminate_enclave;
                }
            }
        }
    }

    ret = 0;

    /* Cleanup. */
exit_terminate_enclave:
    result = oe_terminate_enclave(enclave);
    if (result != OE_OK) {
        fprintf(stderr, "oe_terminate_enclave: %s\n", oe_result_str(result));
    }
exit:
    return ret;
}
