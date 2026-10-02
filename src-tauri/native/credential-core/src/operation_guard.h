#ifndef PRODUCT_OPERATION_GUARD_H
#define PRODUCT_OPERATION_GUARD_H

#include <stdatomic.h>
#include <stdbool.h>

typedef struct {
    atomic_bool busy;
} product_operation_guard;

#define PRODUCT_OPERATION_GUARD_INIT {ATOMIC_VAR_INIT(false)}

// Never waits. The helper owns one process-wide guard across every peer.
bool product_operation_guard_try_acquire(product_operation_guard *guard);
void product_operation_guard_release(product_operation_guard *guard);

#endif
