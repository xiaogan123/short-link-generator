#include "credential_protocol.h"
#include "credential_location.h"

#include <string.h>

bool product_request_id_valid(const char *id, size_t length) {
    if (id == NULL || length != PRODUCT_REQUEST_ID_LENGTH
        || strnlen(id, PRODUCT_REQUEST_ID_LENGTH + 1) != length) return false;
    for (size_t i = 0; i < length; ++i)
        if (!((id[i] >= '0' && id[i] <= '9')
              || (id[i] >= 'a' && id[i] <= 'f'))) return false;
    return true;
}

bool product_nonce_valid(const uint8_t *nonce, size_t length) {
    if (nonce == NULL || length != PRODUCT_NONCE_LENGTH) return false;
    uint8_t combined = 0;
    for (size_t i = 0; i < length; ++i) combined |= nonce[i];
    return combined != 0;
}

bool product_hello_valid(int64_t version, size_t fields, const char *id,
                         size_t id_length, const char *message_type) {
    return version == PRODUCT_PROTOCOL_VERSION && fields == 3
        && product_request_id_valid(id, id_length)
        && message_type != NULL && strcmp(message_type, "hello") == 0;
}

bool product_ready_valid(int64_t version, size_t fields, const char *id,
                         size_t id_length, const char *expected_id,
                         const char *message_type, const uint8_t *nonce,
                         size_t nonce_length) {
    return version == PRODUCT_PROTOCOL_VERSION && fields == 4
        && product_request_id_valid(id, id_length)
        && expected_id != NULL && strcmp(id, expected_id) == 0
        && message_type != NULL && strcmp(message_type, "ready") == 0
        && product_nonce_valid(nonce, nonce_length);
}

bool product_call_valid(int64_t version, size_t fields, const char *id,
                        size_t id_length, const char *hello_id,
                        const char *message_type, const uint8_t *nonce,
                        size_t nonce_length, const uint8_t *expected_nonce,
                        const credential_request *request,
                        const uint8_t *location, size_t location_length) {
    if (version != PRODUCT_PROTOCOL_VERSION || !credential_request_valid(request)
        || fields != ((request->operation == PRODUCT_CURRENT_UPSERT
                       || request->operation == PRODUCT_CURRENT_CREATE_ONLY) ? 9u : 8u)
        || !product_request_id_valid(id, id_length)
        || hello_id == NULL || strcmp(id, hello_id) == 0
        || message_type == NULL || strcmp(message_type, "call") != 0
        || !product_nonce_valid(nonce, nonce_length)
        || expected_nonce == NULL
        || location_length != PRODUCT_LOCATION_ID_LENGTH
        || !product_location_id_valid(location)) return false;
    uint8_t difference = 0;
    for (size_t i = 0; i < PRODUCT_NONCE_LENGTH; ++i)
        difference |= nonce[i] ^ expected_nonce[i];
    return difference == 0;
}

bool product_reply_valid(int64_t version, size_t fields, const char *id,
                         size_t id_length, const char *expected_id,
                         const char *message_type, credential_operation operation,
                         credential_status status, const uint8_t *value,
                         size_t value_length, bool value_field_present) {
    if (version != PRODUCT_PROTOCOL_VERSION
        || !product_request_id_valid(id, id_length)
        || expected_id == NULL || strcmp(id, expected_id) != 0
        || message_type == NULL || strcmp(message_type, "reply") != 0
        || operation < PRODUCT_CURRENT_READ
        || operation > PRODUCT_EXPLICIT_LEGACY_READ
        || status < PRODUCT_OK || status >= PRODUCT_INVALID) return false;
    bool read = operation == PRODUCT_CURRENT_READ
        || operation == PRODUCT_EXPLICIT_LEGACY_READ;
    if ((status == PRODUCT_MISSING && !read)
        || (status == PRODUCT_ALREADY_EXISTS
            && operation != PRODUCT_CURRENT_CREATE_ONLY)) return false;
    bool read_success = read && status == PRODUCT_OK;
    if (read_success)
        return fields == 5 && value_field_present
            && credential_utf8_valid(value, value_length);
    return fields == 4 && !value_field_present
        && value == NULL && value_length == 0;
}
