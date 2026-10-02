#include "identity.h"
#include "entitlements.h"

#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>
#include <string.h>

static bool safe_identifier(const char *identifier) {
    if (identifier == NULL) {
        return false;
    }
    const size_t length = strnlen(identifier, 97);
    if (length == 0 || length > 96) {
        return false;
    }
    for (size_t i = 0; i < length; ++i) {
        const char c = identifier[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || c == '.' || c == '-')) {
            return false;
        }
    }
    return true;
}

bool verify_xpc_sender(xpc_object_t message, const expected_identity *expected) {
    if (message == NULL || xpc_get_type(message) != XPC_TYPE_DICTIONARY
        || !identity_pin_configured(expected)
        || !safe_identifier(expected->identifier)) {
        return false;
    }

    bool accepted = false;
    SecCodeRef code = NULL;
    SecRequirementRef requirement = NULL;
    CFDictionaryRef information = NULL;
    CFStringRef requirement_text = NULL;
    CFDataRef certificate_data = NULL;
    if (SecCodeCreateWithXPCMessage(message, kSecCSDefaultFlags, &code) != errSecSuccess
        || code == NULL) {
        goto done;
    }

    char expression[128];
    const int printed = snprintf(expression, sizeof(expression),
                                 "identifier \"%s\"", expected->identifier);
    if (printed < 0 || (size_t)printed >= sizeof(expression)) {
        goto done;
    }
    requirement_text = CFStringCreateWithCString(
        kCFAllocatorDefault, expression, kCFStringEncodingUTF8);
    if (requirement_text == NULL
        || SecRequirementCreateWithString(requirement_text, kSecCSDefaultFlags,
                                          &requirement) != errSecSuccess
        || requirement == NULL
        || SecCodeCheckValidity(code, kSecCSDefaultFlags,
                                requirement) != errSecSuccess
        || SecCodeCopySigningInformation((SecStaticCodeRef)code,
                                         kSecCSSigningInformation,
                                         &information) != errSecSuccess
        || information == NULL) {
        goto done;
    }

    CFTypeRef identifier_value = CFDictionaryGetValue(information, kSecCodeInfoIdentifier);
    CFTypeRef flags_value = CFDictionaryGetValue(information, kSecCodeInfoFlags);
    CFTypeRef certificates_value = CFDictionaryGetValue(information,
                                                         kSecCodeInfoCertificates);
    if (identifier_value == NULL || CFGetTypeID(identifier_value) != CFStringGetTypeID()
        || flags_value == NULL || CFGetTypeID(flags_value) != CFNumberGetTypeID()
        || certificates_value == NULL
        || CFGetTypeID(certificates_value) != CFArrayGetTypeID()
        || CFArrayGetCount((CFArrayRef)certificates_value) < 1) {
        goto done;
    }
    char identifier[128];
    if (!CFStringGetCString((CFStringRef)identifier_value, identifier,
                            sizeof(identifier), kCFStringEncodingUTF8)) {
        goto done;
    }
    int64_t signing_flags = 0;
    if (!CFNumberGetValue((CFNumberRef)flags_value, kCFNumberSInt64Type,
                          &signing_flags)) {
        goto done;
    }
    CFTypeRef certificate = CFArrayGetValueAtIndex(
        (CFArrayRef)certificates_value, 0);
    if (certificate == NULL || CFGetTypeID(certificate) != SecCertificateGetTypeID()) {
        goto done;
    }
    certificate_data = SecCertificateCopyData((SecCertificateRef)certificate);
    if (certificate_data == NULL || CFDataGetLength(certificate_data) < 1
        || CFDataGetLength(certificate_data) > INT32_MAX) {
        goto done;
    }
    uint8_t certificate_hash[CC_SHA256_DIGEST_LENGTH];
    if (CC_SHA256(CFDataGetBytePtr(certificate_data),
                  (CC_LONG)CFDataGetLength(certificate_data),
                  certificate_hash) == NULL) {
        goto done;
    }

    const uint8_t *cdhash = NULL;
    size_t cdhash_length = 0;
    if (expected->cdhash != NULL) {
        CFTypeRef unique_value = CFDictionaryGetValue(information, kSecCodeInfoUnique);
        if (unique_value == NULL || CFGetTypeID(unique_value) != CFDataGetTypeID()) {
            goto done;
        }
        cdhash = CFDataGetBytePtr((CFDataRef)unique_value);
        cdhash_length = (size_t)CFDataGetLength((CFDataRef)unique_value);
    }
    const observed_identity observed = {
        .valid_signature = true,
        .hardened_runtime = ((uint64_t)signing_flags & kSecCodeSignatureRuntime) != 0,
        .forbidden_entitlements = !entitlements_allowed(information),
        .identifier = identifier,
        .certificate_sha256 = certificate_hash,
        .certificate_length = sizeof(certificate_hash),
        .cdhash = cdhash,
        .cdhash_length = cdhash_length,
    };
    accepted = identity_matches(&observed, expected);

done:
    if (certificate_data != NULL) CFRelease(certificate_data);
    if (information != NULL) CFRelease(information);
    if (requirement != NULL) CFRelease(requirement);
    if (requirement_text != NULL) CFRelease(requirement_text);
    if (code != NULL) CFRelease(code);
    return accepted;
}
