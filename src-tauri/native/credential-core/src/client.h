#ifndef PRODUCT_CREDENTIAL_CLIENT_H
#define PRODUCT_CREDENTIAL_CLIENT_H

#include "credential_policy.h"
#include "credential_location.h"

// Draft C ABI. request strings must be NUL terminated. A successful read
// returns a malloc-owned byte buffer, which must be cleared using this ABI.
// One invocation creates one connection and makes at most one credential call.
credential_status product_credential_call(const credential_request *request,
                                          const uint8_t expected_location[PRODUCT_LOCATION_ID_LENGTH],
                                          credential_result *result);
void product_credential_result_clear(credential_result *result);

#endif
