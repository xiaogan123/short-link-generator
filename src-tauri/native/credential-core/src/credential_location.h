#ifndef PRODUCT_CREDENTIAL_LOCATION_H
#define PRODUCT_CREDENTIAL_LOCATION_H

#include <Security/Security.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#define PRODUCT_LOCATION_ID_LENGTH 32u
// Outside Security.framework's status range. In particular this is never
// errSecItemNotFound, which has item-level meaning in the policy layer.
#define PRODUCT_LOCATION_UNAVAILABLE (-70000)

typedef struct {
    OSStatus (*copy_default)(SecPreferencesDomain, SecKeychainRef *);
    bool (*ref_valid)(SecKeychainRef);
    OSStatus (*get_path)(SecKeychainRef, UInt32 *, char *);
    void (*release)(SecKeychainRef);
} product_location_api;

bool product_location_id_valid(const uint8_t identity[PRODUCT_LOCATION_ID_LENGTH]);
bool product_location_id_equal(const uint8_t a[PRODUCT_LOCATION_ID_LENGTH],
                               const uint8_t b[PRODUCT_LOCATION_ID_LENGTH]);
// Pure Security-API seam: callbacks can be synthetic; no Keychain item call is
// made. On success caller owns exactly one returned ref.
OSStatus product_location_resolve(const product_location_api *api, uid_t user,
                                  const uint8_t *expected,
                                  SecKeychainRef *selected,
                                  uint8_t identity[PRODUCT_LOCATION_ID_LENGTH]);
OSStatus product_location_resolve_default(const uint8_t *expected,
                                          SecKeychainRef *selected,
                                          uint8_t identity[PRODUCT_LOCATION_ID_LENGTH]);
int32_t product_credential_location_snapshot(
    uint8_t identity[PRODUCT_LOCATION_ID_LENGTH]);

#endif
