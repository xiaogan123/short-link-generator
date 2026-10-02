#ifndef PHASE3_SECURE_ZERO_H
#define PHASE3_SECURE_ZERO_H

#include <stddef.h>

static inline void phase3_secure_zero(void *buffer, size_t length) {
    volatile unsigned char *cursor = buffer;
    while (length-- > 0) *cursor++ = 0;
}

#endif
