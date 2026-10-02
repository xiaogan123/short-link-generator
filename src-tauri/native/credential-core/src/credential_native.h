#ifndef PRODUCT_CREDENTIAL_NATIVE_H
#define PRODUCT_CREDENTIAL_NATIVE_H

#include "credential_policy.h"
#include "credential_location.h"

// The helper calls these only after audit-token and protocol validation.
// All callbacks independently enforce the compiled execution gate.
extern const credential_ops PRODUCT_NATIVE_OPS;

#endif
