#include "policy.h"

#include <string.h>

static bool any_nonzero(const uint8_t *bytes, size_t length) {
    if (bytes == NULL) {
        return false;
    }
    uint8_t combined = 0;
    for (size_t i = 0; i < length; ++i) {
        combined |= bytes[i];
    }
    return combined != 0;
}

static bool bytes_equal(const uint8_t *left, const uint8_t *right, size_t length) {
    uint8_t difference = 0;
    for (size_t i = 0; i < length; ++i) {
        difference |= left[i] ^ right[i];
    }
    return difference == 0;
}

bool identity_pin_configured(const expected_identity *expected) {
    if (expected == NULL || expected->identifier == NULL
        || expected->identifier[0] == '\0'
        || expected->certificate_length != 32
        || !any_nonzero(expected->certificate_sha256, 32)) {
        return false;
    }
    if (expected->cdhash == NULL) {
        return expected->cdhash_length == 0;
    }
    return (expected->cdhash_length == 20 || expected->cdhash_length == 32)
        && any_nonzero(expected->cdhash, expected->cdhash_length);
}

bool identity_matches(const observed_identity *observed,
                      const expected_identity *expected) {
    if (!identity_pin_configured(expected) || observed == NULL
        || !observed->valid_signature || !observed->hardened_runtime
        || observed->forbidden_entitlements || observed->identifier == NULL
        || strcmp(observed->identifier, expected->identifier) != 0
        || observed->certificate_sha256 == NULL
        || observed->certificate_length != expected->certificate_length
        || !bytes_equal(observed->certificate_sha256,
                        expected->certificate_sha256, 32)) {
        return false;
    }
    if (expected->cdhash == NULL) {
        return true;
    }
    return observed->cdhash != NULL
        && observed->cdhash_length == expected->cdhash_length
        && bytes_equal(observed->cdhash, expected->cdhash,
                       expected->cdhash_length);
}
