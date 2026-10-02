#ifndef PRODUCT_XPC_CREDENTIAL_H
#define PRODUCT_XPC_CREDENTIAL_H

#include "credential_protocol.h"
#include "credential_location.h"
#include <xpc/xpc.h>

// Parsing borrows value bytes from the XPC message; dispatch synchronously.
xpc_object_t product_xpc_make_hello(const char *id);
bool product_xpc_parse_hello(xpc_object_t message,
                             char id[PRODUCT_REQUEST_ID_LENGTH + 1]);
xpc_object_t product_xpc_make_ready(xpc_object_t hello, const char *id,
                                    const uint8_t nonce[PRODUCT_NONCE_LENGTH]);
bool product_xpc_parse_ready(xpc_object_t message, const char *expected_id,
                             uint8_t nonce[PRODUCT_NONCE_LENGTH]);
xpc_object_t product_xpc_make_call(const char *id,
                                   const uint8_t nonce[PRODUCT_NONCE_LENGTH],
                                   const credential_request *request,
                                   const uint8_t location[PRODUCT_LOCATION_ID_LENGTH]);
bool product_xpc_parse_call(xpc_object_t message, const char *hello_id,
                            const uint8_t expected_nonce[PRODUCT_NONCE_LENGTH],
                            char id[PRODUCT_REQUEST_ID_LENGTH + 1],
                            credential_request *request,
                            uint8_t location[PRODUCT_LOCATION_ID_LENGTH]);
xpc_object_t product_xpc_make_reply(xpc_object_t call, const char *id,
                                    credential_operation operation,
                                    const credential_result *result);
bool product_xpc_parse_reply(xpc_object_t message, const char *expected_id,
                             credential_operation operation,
                             credential_result *result);

#endif
