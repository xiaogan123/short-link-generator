#include "credential_location.h"
#include "execution_gate.h"

#include <CommonCrypto/CommonDigest.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static OSStatus location_error(OSStatus code) {
    // Resolver failure is never proof of an absent item. Preserve only
    // unambiguous user/authentication outcomes.
    if (code == errSecAuthFailed || code == errSecInteractionNotAllowed
        || code == errSecInteractionRequired || code == errSecUserCanceled)
        return code;
    return PRODUCT_LOCATION_UNAVAILABLE;
}

bool product_location_id_valid(const uint8_t identity[PRODUCT_LOCATION_ID_LENGTH]) {
    if (identity == NULL) return false;
    uint8_t combined = 0;
    for (size_t i = 0; i < PRODUCT_LOCATION_ID_LENGTH; ++i)
        combined |= identity[i];
    return combined != 0;
}

bool product_location_id_equal(const uint8_t a[PRODUCT_LOCATION_ID_LENGTH],
                               const uint8_t b[PRODUCT_LOCATION_ID_LENGTH]) {
    if (a == NULL || b == NULL) return false;
    uint8_t difference = 0;
    for (size_t i = 0; i < PRODUCT_LOCATION_ID_LENGTH; ++i)
        difference |= a[i] ^ b[i];
    return difference == 0;
}

static void hash_u64(CC_SHA256_CTX *hash, uint64_t number) {
    uint8_t encoded[8];
    for (size_t i = 0; i < sizeof(encoded); ++i)
        encoded[sizeof(encoded) - 1 - i] = (uint8_t)(number >> (8u * i));
    CC_SHA256_Update(hash, encoded, (CC_LONG)sizeof(encoded));
}

static bool identity_for_path(const char *path, uid_t user,
                              uint8_t identity[PRODUCT_LOCATION_ID_LENGTH]) {
    if (path == NULL || path[0] != '/') return false;
    struct stat before, after;
    if (lstat(path, &before) != 0 || !S_ISREG(before.st_mode)
        || before.st_uid != user || before.st_nlink != 1) return false;
    char canonical[PATH_MAX];
    if (realpath(path, canonical) == NULL || strcmp(path, canonical) != 0
        || stat(path, &after) != 0 || !S_ISREG(after.st_mode)
        || after.st_uid != user || after.st_nlink != 1
        || after.st_dev != before.st_dev || after.st_ino != before.st_ino)
        return false;
    static const char domain[] = "shortlink-keychain-user-default-v1";
    const size_t length = strlen(path);
    CC_SHA256_CTX hash;
    if (CC_SHA256_Init(&hash) != 1) return false;
    CC_SHA256_Update(&hash, domain, (CC_LONG)sizeof(domain));
    hash_u64(&hash, (uint64_t)length);
    CC_SHA256_Update(&hash, path, (CC_LONG)length);
    hash_u64(&hash, (uint64_t)before.st_uid);
    hash_u64(&hash, (uint64_t)before.st_dev);
    hash_u64(&hash, (uint64_t)before.st_ino);
    return CC_SHA256_Final(identity, &hash) == 1
        && product_location_id_valid(identity);
}

OSStatus product_location_resolve(const product_location_api *api, uid_t user,
                                  const uint8_t *expected,
                                  SecKeychainRef *selected,
                                  uint8_t identity[PRODUCT_LOCATION_ID_LENGTH]) {
    if (selected == NULL || identity == NULL) return PRODUCT_LOCATION_UNAVAILABLE;
    *selected = NULL;
    memset(identity, 0, PRODUCT_LOCATION_ID_LENGTH);
    if (api == NULL || api->copy_default == NULL || api->ref_valid == NULL
        || api->get_path == NULL
        || api->release == NULL
        || (expected != NULL && !product_location_id_valid(expected)))
        return PRODUCT_LOCATION_UNAVAILABLE;

    SecKeychainRef ref = NULL;
    OSStatus code = api->copy_default(kSecPreferencesDomainUser, &ref);
    if (code != errSecSuccess || ref == NULL) {
        if (ref != NULL) api->release(ref);
        return location_error(code);
    }
    if (!api->ref_valid(ref)) {
        api->release(ref);
        return PRODUCT_LOCATION_UNAVAILABLE;
    }
    char path[PATH_MAX + 1];
    memset(path, 0xa5, sizeof(path));
    UInt32 length = PATH_MAX;
    code = api->get_path(ref, &length, path);
    if (code != errSecSuccess || length == 0 || length >= PATH_MAX
        || path[length] != '\0' || memchr(path, '\0', length) != NULL
        || !identity_for_path(path, user, identity)
        || (expected != NULL && !product_location_id_equal(expected, identity))) {
        api->release(ref);
        memset(identity, 0, PRODUCT_LOCATION_ID_LENGTH);
        return location_error(code);
    }
    *selected = ref;
    return errSecSuccess;
}

static void release_keychain(SecKeychainRef keychain) {
    CFRelease(keychain);
}

static bool keychain_ref_valid(SecKeychainRef keychain) {
    return CFGetTypeID(keychain) == SecKeychainGetTypeID();
}

OSStatus product_location_resolve_default(const uint8_t *expected,
                                          SecKeychainRef *selected,
                                          uint8_t identity[PRODUCT_LOCATION_ID_LENGTH]) {
    if (selected == NULL || identity == NULL) return PRODUCT_LOCATION_UNAVAILABLE;
    *selected = NULL;
    memset(identity, 0, PRODUCT_LOCATION_ID_LENGTH);
    if (!PRODUCT_EXECUTION_ALLOWED || getuid() != geteuid())
        return PRODUCT_LOCATION_UNAVAILABLE;
    const product_location_api api = {
        SecKeychainCopyDomainDefault, keychain_ref_valid,
        SecKeychainGetPath, release_keychain
    };
    return product_location_resolve(&api, getuid(), expected, selected, identity);
}

int32_t product_credential_location_snapshot(
    uint8_t identity[PRODUCT_LOCATION_ID_LENGTH]) {
    if (identity == NULL) return PRODUCT_LOCATION_UNAVAILABLE;
    SecKeychainRef keychain = NULL;
    OSStatus code = product_location_resolve_default(NULL, &keychain, identity);
    if (keychain != NULL) CFRelease(keychain);
    return code;
}
