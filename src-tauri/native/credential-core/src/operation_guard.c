#include "operation_guard.h"

bool product_operation_guard_try_acquire(product_operation_guard *guard) {
    if (guard == NULL) return false;
    bool expected = false;
    return atomic_compare_exchange_strong_explicit(
        &guard->busy, &expected, true,
        memory_order_acq_rel, memory_order_acquire);
}

void product_operation_guard_release(product_operation_guard *guard) {
    if (guard != NULL)
        atomic_store_explicit(&guard->busy, false, memory_order_release);
}
