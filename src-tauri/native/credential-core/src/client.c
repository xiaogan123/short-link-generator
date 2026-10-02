#include "client.h"
#include "credential_protocol.h"
#include "execution_gate.h"
#include "identity.h"
#include "pins.h"
#include "process_limits.h"
#include "secure_zero.h"
#include "xpc_credential.h"

#include <dispatch/dispatch.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <xpc/xpc.h>

typedef struct {
    atomic_uint references;
    dispatch_semaphore_t complete;
    xpc_object_t reply;
} reply_box;

static void release_box(reply_box *box) {
    if (atomic_fetch_sub_explicit(&box->references, 1,
                                  memory_order_acq_rel) == 1) {
        if (box->reply != NULL) xpc_release(box->reply);
        dispatch_release(box->complete);
        free(box);
    }
}

static xpc_object_t await_reply(xpc_connection_t connection,
                                xpc_object_t request, uint64_t seconds) {
    reply_box *box = calloc(1, sizeof(*box));
    if (box == NULL) return NULL;
    atomic_init(&box->references, 2);
    box->complete = dispatch_semaphore_create(0);
    if (box->complete == NULL) { free(box); return NULL; }
    xpc_connection_send_message_with_reply(
        connection, request, dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0),
        ^(xpc_object_t response) {
            if (response != NULL) box->reply = xpc_retain(response);
            dispatch_semaphore_signal(box->complete);
            release_box(box);
        });
    bool timed_out = dispatch_semaphore_wait(
        box->complete, dispatch_time(DISPATCH_TIME_NOW, seconds * NSEC_PER_SEC)) != 0;
    xpc_object_t reply = NULL;
    if (!timed_out && box->reply != NULL) reply = xpc_retain(box->reply);
    release_box(box);
    return reply;
}

static void make_request_id(char id[PRODUCT_REQUEST_ID_LENGTH + 1]) {
    uint8_t random_bytes[PRODUCT_REQUEST_ID_LENGTH / 2];
    static const char hex[] = "0123456789abcdef";
    arc4random_buf(random_bytes, sizeof(random_bytes));
    for (size_t i = 0; i < sizeof(random_bytes); ++i) {
        id[i * 2] = hex[random_bytes[i] >> 4];
        id[i * 2 + 1] = hex[random_bytes[i] & 15];
    }
    id[PRODUCT_REQUEST_ID_LENGTH] = '\0';
    phase3_secure_zero(random_bytes, sizeof(random_bytes));
}

void product_credential_result_clear(credential_result *result) {
    credential_result_clear(result);
}

credential_status product_credential_call(const credential_request *request,
                                          const uint8_t expected_location[PRODUCT_LOCATION_ID_LENGTH],
                                          credential_result *result) {
    if (result == NULL) return PRODUCT_INVALID;
    *result = (credential_result){PRODUCT_INVALID, NULL, 0};
    if (!credential_request_valid(request)
        || !product_location_id_valid(expected_location)) return PRODUCT_INVALID;
    if (!PRODUCT_EXECUTION_ALLOWED) {
        result->status = PRODUCT_UNAVAILABLE;
        return result->status;
    }
    if (!phase3_prepare_process()) {
        result->status = PRODUCT_UNAVAILABLE;
        return result->status;
    }
    const expected_identity helper_identity = product_expected_helper();
    if (!identity_pin_configured(&helper_identity)) {
        result->status = PRODUCT_UNAVAILABLE;
        return result->status;
    }
    xpc_connection_t connection = xpc_connection_create(
        PRODUCT_HELPER_IDENTIFIER, NULL);
    if (connection == NULL) {
        result->status = PRODUCT_IPC_FAILURE;
        return result->status;
    }
    xpc_connection_set_event_handler(connection, ^(xpc_object_t event) {
        (void)event;
    });
    xpc_connection_resume(connection);

    char hello_id[PRODUCT_REQUEST_ID_LENGTH + 1];
    make_request_id(hello_id);
    xpc_object_t hello = product_xpc_make_hello(hello_id);
    if (hello == NULL) goto ipc_failure;
    xpc_object_t ready = await_reply(connection, hello, 8);
    xpc_release(hello);
    uint8_t nonce[PRODUCT_NONCE_LENGTH] = {0};
    bool authenticated = ready != NULL
        && verify_xpc_sender(ready, &helper_identity)
        && product_xpc_parse_ready(ready, hello_id, nonce);
    if (ready != NULL) xpc_release(ready);
    if (!authenticated) goto ipc_failure;

    // Secret request construction occurs only after helper authentication.
    char call_id[PRODUCT_REQUEST_ID_LENGTH + 1];
    make_request_id(call_id);
    if (strcmp(call_id, hello_id) == 0) {
        phase3_secure_zero(nonce, sizeof(nonce));
        goto ipc_failure;
    }
    xpc_object_t call = product_xpc_make_call(
        call_id, nonce, request, expected_location);
    phase3_secure_zero(nonce, sizeof(nonce));
    if (call == NULL) goto ipc_failure;
    xpc_object_t reply = await_reply(connection, call, 120);
    xpc_release(call);
    // A client timeout does not withdraw an OS SecurityAgent prompt. The
    // adapter must treat IPC_FAILURE as unknown and must not replay writes.
    if (reply == NULL) goto ipc_failure;
    bool accepted = verify_xpc_sender(reply, &helper_identity)
        && product_xpc_parse_reply(reply, call_id, request->operation, result);
    xpc_release(reply);
    xpc_connection_cancel(connection);
    xpc_release(connection);
    if (!accepted) {
        result->status = PRODUCT_IPC_FAILURE;
        return result->status;
    }
    return result->status;

ipc_failure:
    xpc_connection_cancel(connection);
    xpc_release(connection);
    result->status = PRODUCT_IPC_FAILURE;
    return result->status;
}
