#include "entitlements.h"

#include <Security/Security.h>

bool entitlements_allowed(CFDictionaryRef signing_information) {
    if (signing_information == NULL) {
        return false;
    }
    const CFTypeRef raw = CFDictionaryGetValue(signing_information,
                                                kSecCodeInfoEntitlements);
    const CFTypeRef normalized = CFDictionaryGetValue(signing_information,
                                                       kSecCodeInfoEntitlementsDict);
    if (raw == NULL && normalized == NULL) {
        return true;
    }
    // The normalized dictionary can be absent for a nonstandard entitlement
    // blob. Such a blob must not be treated as an empty entitlement set.
    if (raw == NULL || normalized == NULL
        || CFGetTypeID(raw) != CFDataGetTypeID()
        || CFGetTypeID(normalized) != CFDictionaryGetTypeID()) {
        return false;
    }
    const CFDictionaryRef entitlements = (CFDictionaryRef)normalized;
    const CFStringRef forbidden[] = {
        CFSTR("com.apple.security.get-task-allow"),
        CFSTR("com.apple.security.cs.disable-library-validation"),
        CFSTR("com.apple.security.cs.allow-unsigned-executable-memory"),
        CFSTR("com.apple.security.cs.disable-executable-page-protection"),
        CFSTR("com.apple.security.cs.allow-dyld-environment-variables"),
    };
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
        const CFTypeRef setting = CFDictionaryGetValue(entitlements,
                                                        forbidden[i]);
        if (setting != NULL && setting != kCFBooleanFalse) {
            return false;
        }
    }
    return true;
}
