#ifndef PRODUCT_CREDENTIAL_POLICY_H
#define PRODUCT_CREDENTIAL_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define PRODUCT_VALUE_MAX 16384u
#define PRODUCT_ACCOUNT_ID_MAX 64u
#define PRODUCT_KEY_MAX (sizeof("selftest-pending") - 1u + 1u + PRODUCT_ACCOUNT_ID_MAX)
#define PRODUCT_CURRENT_SERVICE "org.shortlink.generator.credentials.v2"
#define PRODUCT_LEGACY_SERVICE "org.shortlink.generator"

typedef enum {
    PRODUCT_CURRENT_READ = 1,
    PRODUCT_CURRENT_UPSERT,
    PRODUCT_CURRENT_DELETE,
    PRODUCT_CURRENT_CREATE_ONLY,
    PRODUCT_EXPLICIT_LEGACY_READ
} credential_operation;

typedef enum {
    PRODUCT_OK = 0,
    PRODUCT_MISSING,
    PRODUCT_DENIED,
    PRODUCT_CANCELLED,
    PRODUCT_UNAVAILABLE,
    PRODUCT_ALREADY_EXISTS,
    PRODUCT_INVALID,
    PRODUCT_IPC_FAILURE
} credential_status;

typedef struct {
    credential_operation operation;
    const char *kind;
    const char *account_id;
    const uint8_t *value;
    size_t value_length;
} credential_request;

// A successful read owns a malloc buffer; the caller must clear it.
typedef struct {
    credential_status status;
    uint8_t *value;
    size_t value_length;
} credential_result;

typedef struct {
    int32_t (*get)(void *, const char *, const char *, uint8_t **, size_t *);
    int32_t (*upsert)(void *, const char *, const char *, const uint8_t *, size_t);
    int32_t (*create)(void *, const char *, const char *, const uint8_t *, size_t);
    int32_t (*erase)(void *, const char *, const char *);
} credential_ops;

bool credential_account_id_valid(const char *id);
bool credential_kind_valid(const char *kind);
bool credential_utf8_valid(const uint8_t *value, size_t length);
bool credential_request_valid(const credential_request *request);
bool credential_make_key(const char *kind, const char *id,
                         char key[PRODUCT_KEY_MAX + 1]);
credential_status credential_map_osstatus(int32_t code);
credential_result credential_execute(const credential_request *request,
                                     const credential_ops *ops, void *context);
void credential_result_clear(credential_result *result);
const char *credential_operation_name(credential_operation operation);
bool credential_operation_parse(const char *text, credential_operation *operation);
const char *credential_status_name(credential_status status);
bool credential_status_parse(const char *text, credential_status *status);

#endif
