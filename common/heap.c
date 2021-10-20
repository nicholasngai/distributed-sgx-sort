#include "common/heap.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define HEAP_PARENT(n) (((n) - 1) / 2)
#define HEAP_LEFT(n) ((n) * 2 + 1)
#define HEAP_RIGHT(n) ((n) * 2 + 2)

static void swap(void *a, void *b, size_t size) {
    unsigned char temp[size];
    memcpy(temp, a, size);
    memcpy(a, b, size);
    memcpy(b, temp, size);
}

static void bubble_up(void *arr_, size_t i, size_t elem_size,
        int (*comparator)(const void *a, const void *b, void *aux), void *aux) {
    unsigned char (*arr)[elem_size] = arr_;

    size_t parent = HEAP_PARENT(i);
    if (comparator(&arr[parent], &arr[i], aux) > 0) {
        swap(&arr[parent], &arr[i], elem_size);
        bubble_up(arr, parent, elem_size, comparator, aux);
    }
}

static void bubble_down(void *arr_, size_t i, size_t len, size_t elem_size,
        int (*comparator)(const void *a, const void *b, void *aux), void *aux) {
    unsigned char (*arr)[elem_size] = arr_;

    size_t left = HEAP_LEFT(i);
    size_t right = HEAP_RIGHT(i);
    bool swap_left = false;
    bool swap_right = false;
    if (left < len && comparator(&arr[i], &arr[left], aux) > 0) {
        swap_left = true;
    }
    if (right < len && comparator(&arr[i], &arr[right], aux) > 0) {
        swap_right = true;
    }

    if (swap_left
            && (!swap_right || comparator(&arr[left], &arr[right], aux) <= 0)) {
        swap(&arr[i], &arr[left], elem_size);
        bubble_down(arr, left, len, elem_size, comparator, aux);
    } else if (swap_right) {
        swap(&arr[i], &arr[right], elem_size);
        bubble_down(arr, right, len, elem_size, comparator, aux);
    }
}

void heap_heapify(void *arr, size_t len, size_t elem_size,
        int (*comparator)(const void *a, const void *b, void *aux), void *aux) {
    for (size_t i = HEAP_PARENT(len - 1); i != SIZE_MAX; i--) {
        bubble_down(arr, i, len, elem_size, comparator, aux);
    }
}

void heap_pop(void *out, void *arr_, size_t *len, size_t elem_size,
        int (*comparator)(const void *a, const void *b, void *aux), void *aux) {
    unsigned char (*arr)[elem_size] = arr_;

    memcpy(out, &arr[0], elem_size);
    memcpy(&arr[0], &arr[*len - 1], elem_size);
    (*len)--;
    bubble_down(arr, 0, *len, elem_size, comparator, aux);
}

void heap_push(const void *in, void *arr_, size_t *len, size_t elem_size,
        int (*comparator)(const void *a, const void *b, void *aux), void *aux) {
    unsigned char (*arr)[elem_size] = arr_;

    (*len)++;
    memcpy(&arr[*len - 1], in, elem_size);
    bubble_up(arr, *len - 1, elem_size, comparator, aux);
}

void heap_pushpop(void *out, const void *in, void *arr_, size_t *len,
        size_t elem_size,
        int (*comparator)(const void *a, const void *b, void *aux), void *aux) {
    unsigned char (*arr)[elem_size] = arr_;

    memcpy(out, &arr[0], elem_size);
    memcpy(&arr[0], in, elem_size);
    bubble_down(arr, 0, *len, elem_size, comparator, aux);
}
