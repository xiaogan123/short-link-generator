#ifndef PROTOTYPE_POLICY_H
#define PROTOTYPE_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *identifier;
    const uint8_t *certificate_sha256;
    size_t certificate_length;
    const uint8_t *cdhash;
    size_t cdhash_length;
} expected_identity;

typedef struct {
    bool valid_signature;
    bool hardened_runtime;
    bool forbidden_entitlements;
    const char *identifier;
    const uint8_t *certificate_sha256;
    size_t certificate_length;
    const uint8_t *cdhash;
    size_t cdhash_length;
} observed_identity;

bool identity_pin_configured(const expected_identity *expected);
bool identity_matches(const observed_identity *observed,
                      const expected_identity *expected);

#endif
