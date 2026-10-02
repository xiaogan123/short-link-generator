#ifndef PROTOTYPE_ENTITLEMENTS_H
#define PROTOTYPE_ENTITLEMENTS_H

#include <CoreFoundation/CoreFoundation.h>
#include <stdbool.h>

// Returns false when signing information cannot prove that no dangerous
// entitlement is present. A code object with no entitlements is permitted.
bool entitlements_allowed(CFDictionaryRef signing_information);

#endif
