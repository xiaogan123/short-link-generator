#include "credential_policy.h"
#include "secure_zero.h"

#include <stdlib.h>
#include <string.h>

// These are fixed Security.framework status values. No caller may supply a
// service, keychain path, or arbitrary query.
enum {
    PRODUCT_ERR_NOT_FOUND = -25300,
    PRODUCT_ERR_DUPLICATE = -25299,
    PRODUCT_ERR_AUTH_FAILED = -25293,
    PRODUCT_ERR_INTERACTION_NOT_ALLOWED = -25308,
    PRODUCT_ERR_INTERACTION_REQUIRED = -25315,
    PRODUCT_ERR_USER_CANCELLED = -128
};

static const char *const kinds[] = {
    "token", "selftest", "probe", "selftest-pending"
};

bool credential_account_id_valid(const char *id) {
    if (id == NULL) return false;
    size_t length = strnlen(id, PRODUCT_ACCOUNT_ID_MAX + 1);
    if (length == 0 || length > PRODUCT_ACCOUNT_ID_MAX) return false;
    for (size_t i = 0; i < length; ++i) {
        const unsigned char c = (unsigned char)id[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
              || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
    }
    return true;
}

bool credential_kind_valid(const char *kind) {
    if (kind == NULL) return false;
    size_t length = strnlen(kind, sizeof("selftest-pending"));
    for (size_t i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i) {
        if (strlen(kinds[i]) == length && memcmp(kind, kinds[i], length) == 0)
            return true;
    }
    return false;
}

// Reject overlong sequences, surrogates and code points above U+10FFFF.
bool credential_utf8_valid(const uint8_t *bytes, size_t length) {
    if (length > PRODUCT_VALUE_MAX || (length != 0 && bytes == NULL)) return false;
    for (size_t i = 0; i < length;) {
        uint8_t a = bytes[i++];
        if (a < 0x80) continue;
        if (a >= 0xc2 && a <= 0xdf) {
            if (i >= length || (bytes[i++] & 0xc0) != 0x80) return false;
            continue;
        }
        if (a >= 0xe0 && a <= 0xef) {
            if (i + 1 >= length) return false;
            uint8_t b = bytes[i++], c = bytes[i++];
            if ((b & 0xc0) != 0x80 || (c & 0xc0) != 0x80
                || (a == 0xe0 && b < 0xa0) || (a == 0xed && b >= 0xa0))
                return false;
            continue;
        }
        if (a >= 0xf0 && a <= 0xf4) {
            if (i + 2 >= length) return false;
            uint8_t b = bytes[i++], c = bytes[i++], d = bytes[i++];
            if ((b & 0xc0) != 0x80 || (c & 0xc0) != 0x80
                || (d & 0xc0) != 0x80 || (a == 0xf0 && b < 0x90)
                || (a == 0xf4 && b >= 0x90)) return false;
            continue;
        }
        return false;
    }
    return true;
}

bool credential_request_valid(const credential_request *request) {
    if (request == NULL || request->operation < PRODUCT_CURRENT_READ
        || request->operation > PRODUCT_EXPLICIT_LEGACY_READ
        || !credential_kind_valid(request->kind)
        || !credential_account_id_valid(request->account_id)) return false;
    bool writes = request->operation == PRODUCT_CURRENT_UPSERT
        || request->operation == PRODUCT_CURRENT_CREATE_ONLY;
    if (writes) return credential_utf8_valid(request->value, request->value_length);
    return request->value == NULL && request->value_length == 0;
}

bool credential_make_key(const char *kind, const char *id,
                         char key[PRODUCT_KEY_MAX + 1]) {
    if (key == NULL || !credential_kind_valid(kind)
        || !credential_account_id_valid(id)) return false;
    size_t kind_length = strlen(kind), id_length = strlen(id);
    if (kind_length + 1 + id_length > PRODUCT_KEY_MAX) return false;
    memcpy(key, kind, kind_length);
    key[kind_length] = ':';
    memcpy(key + kind_length + 1, id, id_length);
    key[kind_length + 1 + id_length] = '\0';
    return true;
}

credential_status credential_map_osstatus(int32_t code) {
    switch (code) {
    case 0: return PRODUCT_OK;
    case PRODUCT_ERR_NOT_FOUND: return PRODUCT_MISSING;
    case PRODUCT_ERR_DUPLICATE: return PRODUCT_ALREADY_EXISTS;
    case PRODUCT_ERR_USER_CANCELLED: return PRODUCT_CANCELLED;
    case PRODUCT_ERR_AUTH_FAILED:
    case PRODUCT_ERR_INTERACTION_REQUIRED:
    case PRODUCT_ERR_INTERACTION_NOT_ALLOWED: return PRODUCT_DENIED;
    default: return PRODUCT_UNAVAILABLE;
    }
}

void credential_result_clear(credential_result *result) {
    if (result == NULL) return;
    if (result->value != NULL) {
        phase3_secure_zero(result->value, result->value_length);
        free(result->value);
    }
    *result = (credential_result){0};
}

credential_result credential_execute(const credential_request *request,
                                     const credential_ops *ops, void *context) {
    credential_result result = {PRODUCT_INVALID, NULL, 0};
    if (!credential_request_valid(request) || ops == NULL) return result;
    char key[PRODUCT_KEY_MAX + 1];
    if (!credential_make_key(request->kind, request->account_id, key)) return result;
    const char *service = request->operation == PRODUCT_EXPLICIT_LEGACY_READ
        ? PRODUCT_LEGACY_SERVICE : PRODUCT_CURRENT_SERVICE;
    int32_t code;
    switch (request->operation) {
    case PRODUCT_CURRENT_READ:
    case PRODUCT_EXPLICIT_LEGACY_READ:
        if (ops->get == NULL) return result;
        code = ops->get(context, service, key, &result.value, &result.value_length);
        result.status = credential_map_osstatus(code);
        if (result.status == PRODUCT_OK
            && !credential_utf8_valid(result.value, result.value_length))
            result.status = PRODUCT_UNAVAILABLE;
        if (result.status != PRODUCT_OK) {
            credential_result_clear(&result);
            result.status = credential_map_osstatus(code);
            if (result.status == PRODUCT_OK) result.status = PRODUCT_UNAVAILABLE;
        }
        return result;
    case PRODUCT_CURRENT_UPSERT:
        if (ops->upsert == NULL) return result;
        code = ops->upsert(context, service, key, request->value, request->value_length);
        // A not-found/add race is ambiguous for an upsert. Do not claim the
        // create-only AlreadyExists outcome or automatically replay.
        if (code == PRODUCT_ERR_DUPLICATE || code == PRODUCT_ERR_NOT_FOUND)
            code = -1;
        break;
    case PRODUCT_CURRENT_CREATE_ONLY:
        if (ops->create == NULL) return result;
        code = ops->create(context, service, key, request->value, request->value_length);
        break;
    case PRODUCT_CURRENT_DELETE:
        if (ops->erase == NULL) return result;
        code = ops->erase(context, service, key);
        if (code == PRODUCT_ERR_NOT_FOUND) code = 0; // Existing delete is idempotent.
        if (code == PRODUCT_ERR_DUPLICATE) code = -1;
        break;
    default: return result;
    }
    result.status = credential_map_osstatus(code);
    return result;
}

static const char *const operation_names[] = {
    NULL, "currentRead", "currentUpsert", "currentDelete",
    "currentCreateOnly", "explicitLegacyRead"
};
static const char *const status_names[] = {
    "ok", "missing", "denied", "cancelled", "unavailable",
    "alreadyExists", "invalid", "ipcFailure"
};

const char *credential_operation_name(credential_operation operation) {
    if (operation < PRODUCT_CURRENT_READ || operation > PRODUCT_EXPLICIT_LEGACY_READ)
        return NULL;
    return operation_names[operation];
}
bool credential_operation_parse(const char *text, credential_operation *operation) {
    if (text == NULL || operation == NULL) return false;
    for (int i = PRODUCT_CURRENT_READ; i <= PRODUCT_EXPLICIT_LEGACY_READ; ++i)
        if (strcmp(text, operation_names[i]) == 0) {
            *operation = (credential_operation)i; return true;
        }
    return false;
}
const char *credential_status_name(credential_status status) {
    if (status < PRODUCT_OK || status > PRODUCT_IPC_FAILURE) return NULL;
    return status_names[status];
}
bool credential_status_parse(const char *text, credential_status *status) {
    if (text == NULL || status == NULL) return false;
    for (int i = PRODUCT_OK; i <= PRODUCT_IPC_FAILURE; ++i)
        if (strcmp(text, status_names[i]) == 0) {
            *status = (credential_status)i; return true;
        }
    return false;
}
