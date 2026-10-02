#ifndef PROTOTYPE_IDENTITY_H
#define PROTOTYPE_IDENTITY_H

#include <stdbool.h>
#include <xpc/xpc.h>

#include "policy.h"

// The source identity is the audit token attached by XPC to this exact message.
// No caller-provided PID, path, UID, or message field is an identity input.
bool verify_xpc_sender(xpc_object_t message, const expected_identity *expected);

#endif
