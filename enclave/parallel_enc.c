#include <stdio.h>
#include <openenclave/enclave.h>
#include "parallel_t.h"
#include "synch.h"

static int world_rank;
static int world_size;
static size_t num_threads;

static void wait_for_all_threads(void) {
    static size_t num_threads_waiting;
    static condvar_t all_threads_finished;
    static spinlock_t all_threads_lock;

    spinlock_lock(&all_threads_lock);
    num_threads_waiting++;
    if (num_threads_waiting >= num_threads) {
        condvar_broadcast(&all_threads_finished, &all_threads_lock);
        num_threads_waiting = 0;
    } else {
        condvar_wait(&all_threads_finished, &all_threads_lock);
    }
    spinlock_unlock(&all_threads_lock);
}

void ecall_set_params(int world_rank_, int world_size_, size_t num_threads_) {
    /* Set global parameters. */
    world_rank = world_rank_;
    world_size = world_size_;
    num_threads = num_threads_;
}

void ecall_start_work(size_t thread_id) {
    static spinlock_t print_lock;

    spinlock_lock(&print_lock);
    printf("Spawned node %d thread %lu\n", world_rank, thread_id);
    spinlock_unlock(&print_lock);
    wait_for_all_threads();
    spinlock_lock(&print_lock);
    printf("Released node %d thread %lu\n", world_rank, thread_id);
    spinlock_unlock(&print_lock);
}

int ecall_main(void) {
    /* Start work for this thread. */
    ecall_start_work(0);

    return 0;
}
