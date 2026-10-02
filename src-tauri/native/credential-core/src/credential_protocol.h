#ifndef PRODUCT_CREDENTIAL_PROTOCOL_H
#define PRODUCT_CREDENTIAL_PROTOCOL_H

#include "credential_policy.h"
#include "credential_location.h"

#define PRODUCT_PROTOCOL_VERSION 2
#define PRODUCT_REQUEST_ID_LENGTH 32u
#define PRODUCT_NONCE_LENGTH 16u

bool product_request_id_valid(const char *id, size_t length);
bool product_nonce_valid(const uint8_t *nonce, size_t length);
bool product_hello_valid(int64_t version, size_t fields, const char *id,
                         size_t id_length, const char *message_type);
bool product_ready_valid(int64_t version, size_t fields, const char *id,
                         size_t id_length, const char *expected_id,
                         const char *message_type, const uint8_t *nonce,
                         size_t nonce_length);
bool product_call_valid(int64_t version, size_t fields, const char *id,
                        size_t id_length, const char *hello_id,
                        const char *message_type, const uint8_t *nonce,
                        size_t nonce_length, const uint8_t *expected_nonce,
                        const credential_request *request,
                        const uint8_t *location, size_t location_length);
bool product_reply_valid(int64_t version, size_t fields, const char *id,
                         size_t id_length, const char *expected_id,
                         const char *message_type, credential_operation operation,
                         credential_status status, const uint8_t *value,
                         size_t value_length, bool value_field_present);

#endif
