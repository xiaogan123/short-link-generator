#include "credential_native.h"
#include "credential_location.h"
#include "execution_gate.h"
#include "secure_zero.h"

#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool fixed_query(const char *service, const char *key, bool allow_legacy) {
    if (service == NULL || key == NULL
        || (strcmp(service, PRODUCT_CURRENT_SERVICE) != 0
            && (!allow_legacy || strcmp(service, PRODUCT_LEGACY_SERVICE) != 0)))
        return false;
    size_t length = strnlen(key, PRODUCT_KEY_MAX + 1);
    if (length == 0 || length > PRODUCT_KEY_MAX) return false;
    const char *separator = strchr(key, ':');
    if (separator == NULL || strchr(separator + 1, ':') != NULL) return false;
    size_t kind_length = (size_t)(separator - key);
    if (kind_length == 0 || kind_length >= sizeof("selftest-pending"))
        return false;
    char kind[sizeof("selftest-pending")];
    memcpy(kind, key, kind_length);
    kind[kind_length] = '\0';
    return credential_kind_valid(kind)
        && credential_account_id_valid(separator + 1);
}

static OSStatus selected_user_default(const void *context, SecKeychainRef *keychain) {
    if (context == NULL || keychain == NULL) return PRODUCT_LOCATION_UNAVAILABLE;
    uint8_t identity[PRODUCT_LOCATION_ID_LENGTH];
    OSStatus code = product_location_resolve_default(
        context, keychain, identity);
    phase3_secure_zero(identity, sizeof(identity));
    return code;
}

static int32_t native_get(void *context, const char *service, const char *key,
                          uint8_t **value, size_t *length) {
    if (!PRODUCT_EXECUTION_ALLOWED || !fixed_query(service, key, true)
        || value == NULL || length == NULL) return errSecParam;
    *value = NULL;
    *length = 0;
    SecKeychainRef keychain = NULL;
    OSStatus code = selected_user_default(context, &keychain);
    if (code != errSecSuccess) return code;
    UInt32 native_length = 0;
    void *native_value = NULL;
    code = SecKeychainFindGenericPassword(keychain,
        (UInt32)strlen(service), service, (UInt32)strlen(key), key,
        &native_length, &native_value, NULL);
    CFRelease(keychain);
    if (code != errSecSuccess) {
        if (native_value != NULL) {
            phase3_secure_zero(native_value, native_length);
            SecKeychainItemFreeContent(NULL, native_value);
        }
        return code;
    }
    if (native_length > PRODUCT_VALUE_MAX || (native_length != 0 && native_value == NULL)) {
        code = errSecParam;
    } else {
        uint8_t *copy = malloc(native_length == 0 ? 1 : native_length);
        if (copy == NULL) code = errSecAllocate;
        else {
            if (native_length != 0) memcpy(copy, native_value, native_length);
            *value = copy;
            *length = native_length;
        }
    }
    if (native_value != NULL) {
        phase3_secure_zero(native_value, native_length);
        SecKeychainItemFreeContent(NULL, native_value);
    }
    return code;
}

static int32_t native_create(void *context, const char *service, const char *key,
                             const uint8_t *value, size_t length) {
    if (!PRODUCT_EXECUTION_ALLOWED || !fixed_query(service, key, false)
        || length > PRODUCT_VALUE_MAX || length > UINT32_MAX
        || (length != 0 && value == NULL)) return errSecParam;
    SecKeychainRef keychain = NULL;
    OSStatus code = selected_user_default(context, &keychain);
    if (code != errSecSuccess) return code;
    static const uint8_t empty = 0;
    code = SecKeychainAddGenericPassword(keychain,
        (UInt32)strlen(service), service, (UInt32)strlen(key), key,
        (UInt32)length, value == NULL ? &empty : value, NULL);
    CFRelease(keychain);
    return code; // Duplicate remains errSecDuplicateItem; never overwrite.
}

static int32_t native_upsert(void *context, const char *service, const char *key,
                             const uint8_t *value, size_t length) {
    if (!PRODUCT_EXECUTION_ALLOWED || !fixed_query(service, key, false)
        || length > PRODUCT_VALUE_MAX || length > UINT32_MAX
        || (length != 0 && value == NULL)) return errSecParam;
    SecKeychainRef keychain = NULL;
    OSStatus code = selected_user_default(context, &keychain);
    if (code != errSecSuccess) return code;
    SecKeychainItemRef item = NULL;
    code = SecKeychainFindGenericPassword(keychain,
        (UInt32)strlen(service), service, (UInt32)strlen(key), key,
        NULL, NULL, &item);
    static const uint8_t empty = 0;
    if (code == errSecSuccess && item != NULL) {
        code = SecKeychainItemModifyAttributesAndData(
            item, NULL, (UInt32)length, value == NULL ? &empty : value);
        CFRelease(item);
    } else if (code == errSecItemNotFound && item == NULL) {
        code = SecKeychainAddGenericPassword(keychain,
            (UInt32)strlen(service), service, (UInt32)strlen(key), key,
            (UInt32)length, value == NULL ? &empty : value, NULL);
        // A concurrent duplicate is a failure; no implicit second request.
    } else {
        if (item != NULL) CFRelease(item);
        if (code == errSecSuccess || code == errSecItemNotFound)
            code = PRODUCT_LOCATION_UNAVAILABLE;
    }
    CFRelease(keychain);
    return code;
}

static int32_t native_erase(void *context, const char *service, const char *key) {
    if (!PRODUCT_EXECUTION_ALLOWED || !fixed_query(service, key, false))
        return errSecParam;
    SecKeychainRef keychain = NULL;
    OSStatus code = selected_user_default(context, &keychain);
    if (code != errSecSuccess) return code;
    SecKeychainItemRef item = NULL;
    code = SecKeychainFindGenericPassword(keychain,
        (UInt32)strlen(service), service, (UInt32)strlen(key), key,
        NULL, NULL, &item);
    if (code == errSecSuccess && item != NULL) {
        code = SecKeychainItemDelete(item);
        CFRelease(item);
    } else if (code == errSecItemNotFound && item == NULL) {
        // Only this exact query within the held, proven ref is idempotent.
    } else {
        if (item != NULL) CFRelease(item);
        if (code == errSecSuccess || code == errSecItemNotFound)
            code = PRODUCT_LOCATION_UNAVAILABLE;
    }
    CFRelease(keychain);
    return code;
}

const credential_ops PRODUCT_NATIVE_OPS = {
    native_get, native_upsert, native_create, native_erase
};
