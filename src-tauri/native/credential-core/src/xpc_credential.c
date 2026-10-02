#include "xpc_credential.h"

#include <stdlib.h>
#include <string.h>

static bool read_string(xpc_object_t dict, const char *key,
                        const char **text, size_t *length) {
    xpc_object_t field = xpc_dictionary_get_value(dict, key);
    if (field == NULL || xpc_get_type(field) != XPC_TYPE_STRING) return false;
    *text = xpc_string_get_string_ptr(field);
    *length = xpc_string_get_length(field);
    return *text != NULL && *length <= PRODUCT_ACCOUNT_ID_MAX
        && strlen(*text) == *length;
}

static bool read_header(xpc_object_t dict, const char **id, size_t *id_length,
                        const char **type) {
    size_t type_length;
    xpc_object_t version = xpc_dictionary_get_value(dict, "version");
    return xpc_get_type(dict) == XPC_TYPE_DICTIONARY
        && version != NULL && xpc_get_type(version) == XPC_TYPE_INT64
        && xpc_int64_get_value(version) == PRODUCT_PROTOCOL_VERSION
        && read_string(dict, "requestId", id, id_length)
        && read_string(dict, "messageType", type, &type_length);
}

static xpc_object_t make_message(const char *id, const char *type) {
    xpc_object_t message = xpc_dictionary_create_empty();
    if (message == NULL) return NULL;
    xpc_dictionary_set_int64(message, "version", PRODUCT_PROTOCOL_VERSION);
    xpc_dictionary_set_string(message, "requestId", id);
    xpc_dictionary_set_string(message, "messageType", type);
    return message;
}

xpc_object_t product_xpc_make_hello(const char *id) {
    if (!product_request_id_valid(id, PRODUCT_REQUEST_ID_LENGTH)) return NULL;
    return make_message(id, "hello");
}

bool product_xpc_parse_hello(xpc_object_t message,
                             char id[PRODUCT_REQUEST_ID_LENGTH + 1]) {
    if (message == NULL || id == NULL
        || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return false;
    const char *raw_id, *type;
    size_t id_length;
    if (!read_header(message, &raw_id, &id_length, &type)
        || !product_hello_valid(PRODUCT_PROTOCOL_VERSION,
                                xpc_dictionary_get_count(message),
                                raw_id, id_length, type)) return false;
    memcpy(id, raw_id, PRODUCT_REQUEST_ID_LENGTH + 1);
    return true;
}

xpc_object_t product_xpc_make_ready(xpc_object_t hello, const char *id,
                                    const uint8_t nonce[PRODUCT_NONCE_LENGTH]) {
    if (hello == NULL || !product_request_id_valid(id, PRODUCT_REQUEST_ID_LENGTH)
        || !product_nonce_valid(nonce, PRODUCT_NONCE_LENGTH)) return NULL;
    xpc_object_t reply = xpc_dictionary_create_reply(hello);
    if (reply == NULL) return NULL;
    xpc_dictionary_set_int64(reply, "version", PRODUCT_PROTOCOL_VERSION);
    xpc_dictionary_set_string(reply, "requestId", id);
    xpc_dictionary_set_string(reply, "messageType", "ready");
    xpc_dictionary_set_data(reply, "nonce", nonce, PRODUCT_NONCE_LENGTH);
    return reply;
}

bool product_xpc_parse_ready(xpc_object_t message, const char *expected_id,
                             uint8_t nonce[PRODUCT_NONCE_LENGTH]) {
    if (message == NULL || nonce == NULL
        || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return false;
    const char *id, *type;
    size_t id_length;
    xpc_object_t field = xpc_dictionary_get_value(message, "nonce");
    if (!read_header(message, &id, &id_length, &type)
        || field == NULL || xpc_get_type(field) != XPC_TYPE_DATA
        || !product_ready_valid(PRODUCT_PROTOCOL_VERSION,
                                xpc_dictionary_get_count(message), id,
                                id_length, expected_id, type,
                                xpc_data_get_bytes_ptr(field),
                                xpc_data_get_length(field))) return false;
    memcpy(nonce, xpc_data_get_bytes_ptr(field), PRODUCT_NONCE_LENGTH);
    return true;
}

xpc_object_t product_xpc_make_call(const char *id,
                                   const uint8_t nonce[PRODUCT_NONCE_LENGTH],
                                   const credential_request *request,
                                   const uint8_t location[PRODUCT_LOCATION_ID_LENGTH]) {
    if (!product_request_id_valid(id, PRODUCT_REQUEST_ID_LENGTH)
        || !product_nonce_valid(nonce, PRODUCT_NONCE_LENGTH)
        || !credential_request_valid(request)
        || !product_location_id_valid(location)) return NULL;
    xpc_object_t message = make_message(id, "call");
    if (message == NULL) return NULL;
    xpc_dictionary_set_data(message, "nonce", nonce, PRODUCT_NONCE_LENGTH);
    xpc_dictionary_set_data(message, "location", location, PRODUCT_LOCATION_ID_LENGTH);
    xpc_dictionary_set_string(message, "operation",
                              credential_operation_name(request->operation));
    xpc_dictionary_set_string(message, "kind", request->kind);
    xpc_dictionary_set_string(message, "accountId", request->account_id);
    if (request->operation == PRODUCT_CURRENT_UPSERT
        || request->operation == PRODUCT_CURRENT_CREATE_ONLY) {
        static const uint8_t empty = 0;
        xpc_dictionary_set_data(message, "value",
                                request->value == NULL ? &empty : request->value,
                                request->value_length);
    }
    return message;
}

bool product_xpc_parse_call(xpc_object_t message, const char *hello_id,
                            const uint8_t expected_nonce[PRODUCT_NONCE_LENGTH],
                            char id[PRODUCT_REQUEST_ID_LENGTH + 1],
                            credential_request *request,
                            uint8_t location[PRODUCT_LOCATION_ID_LENGTH]) {
    if (message == NULL || id == NULL || request == NULL || location == NULL
        || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return false;
    memset(location, 0, PRODUCT_LOCATION_ID_LENGTH);
    const char *raw_id, *type, *operation_name, *kind, *account_id;
    size_t id_length, operation_length, kind_length, account_length;
    xpc_object_t nonce = xpc_dictionary_get_value(message, "nonce");
    xpc_object_t location_field = xpc_dictionary_get_value(message, "location");
    if (!read_header(message, &raw_id, &id_length, &type)
        || !read_string(message, "operation", &operation_name, &operation_length)
        || !read_string(message, "kind", &kind, &kind_length)
        || !read_string(message, "accountId", &account_id, &account_length)
        || nonce == NULL || xpc_get_type(nonce) != XPC_TYPE_DATA
        || location_field == NULL
        || xpc_get_type(location_field) != XPC_TYPE_DATA) return false;
    credential_operation operation;
    if (!credential_operation_parse(operation_name, &operation)) return false;
    xpc_object_t value = xpc_dictionary_get_value(message, "value");
    bool writes = operation == PRODUCT_CURRENT_UPSERT
        || operation == PRODUCT_CURRENT_CREATE_ONLY;
    if ((writes && (value == NULL || xpc_get_type(value) != XPC_TYPE_DATA))
        || (!writes && value != NULL)) return false;
    *request = (credential_request){
        operation, kind, account_id,
        writes ? xpc_data_get_bytes_ptr(value) : NULL,
        writes ? xpc_data_get_length(value) : 0
    };
    if (!product_call_valid(PRODUCT_PROTOCOL_VERSION,
                            xpc_dictionary_get_count(message),
                            raw_id, id_length, hello_id, type,
                            xpc_data_get_bytes_ptr(nonce),
                            xpc_data_get_length(nonce), expected_nonce,
                            request, xpc_data_get_bytes_ptr(location_field),
                            xpc_data_get_length(location_field))) {
        *request = (credential_request){0};
        return false;
    }
    memcpy(id, raw_id, PRODUCT_REQUEST_ID_LENGTH + 1);
    memcpy(location, xpc_data_get_bytes_ptr(location_field),
           PRODUCT_LOCATION_ID_LENGTH);
    return true;
}

xpc_object_t product_xpc_make_reply(xpc_object_t call, const char *id,
                                    credential_operation operation,
                                    const credential_result *result) {
    if (call == NULL || !product_request_id_valid(id, PRODUCT_REQUEST_ID_LENGTH)
        || result == NULL || result->status >= PRODUCT_INVALID) return NULL;
    bool read_success = (operation == PRODUCT_CURRENT_READ
                         || operation == PRODUCT_EXPLICIT_LEGACY_READ)
        && result->status == PRODUCT_OK;
    if (!product_reply_valid(PRODUCT_PROTOCOL_VERSION,
                             read_success ? 5 : 4,
                             id, PRODUCT_REQUEST_ID_LENGTH, id, "reply",
                             operation, result->status,
                             read_success ? result->value : NULL,
                             read_success ? result->value_length : 0,
                             read_success)) return NULL;
    xpc_object_t reply = xpc_dictionary_create_reply(call);
    if (reply == NULL) return NULL;
    xpc_dictionary_set_int64(reply, "version", PRODUCT_PROTOCOL_VERSION);
    xpc_dictionary_set_string(reply, "requestId", id);
    xpc_dictionary_set_string(reply, "messageType", "reply");
    xpc_dictionary_set_string(reply, "status", credential_status_name(result->status));
    if (read_success) {
        static const uint8_t empty = 0;
        xpc_dictionary_set_data(reply, "value",
                                result->value == NULL ? &empty : result->value,
                                result->value_length);
    }
    return reply;
}

bool product_xpc_parse_reply(xpc_object_t message, const char *expected_id,
                             credential_operation operation,
                             credential_result *result) {
    if (message == NULL || result == NULL
        || xpc_get_type(message) != XPC_TYPE_DICTIONARY) return false;
    const char *id, *type, *raw_status;
    size_t id_length, status_length;
    if (!read_header(message, &id, &id_length, &type)
        || !read_string(message, "status", &raw_status, &status_length)) return false;
    credential_status status;
    if (!credential_status_parse(raw_status, &status)) return false;
    xpc_object_t value_field = xpc_dictionary_get_value(message, "value");
    if (value_field != NULL && xpc_get_type(value_field) != XPC_TYPE_DATA)
        return false;
    const uint8_t *value = value_field == NULL ? NULL
        : xpc_data_get_bytes_ptr(value_field);
    size_t length = value_field == NULL ? 0 : xpc_data_get_length(value_field);
    if (!product_reply_valid(PRODUCT_PROTOCOL_VERSION,
                             xpc_dictionary_get_count(message),
                             id, id_length, expected_id, type, operation,
                             status, value, length, value_field != NULL))
        return false;
    credential_result parsed = {status, NULL, 0};
    if (value_field != NULL) {
        parsed.value = malloc(length == 0 ? 1 : length);
        if (parsed.value == NULL) return false;
        if (length != 0) memcpy(parsed.value, value, length);
        parsed.value_length = length;
    }
    *result = parsed;
    return true;
}
