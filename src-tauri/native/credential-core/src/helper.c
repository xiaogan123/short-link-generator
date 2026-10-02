#include "credential_native.h"
#include "execution_gate.h"
#include "identity.h"
#include "operation_guard.h"
#include "pins.h"
#include "process_limits.h"
#include "secure_zero.h"
#include "xpc_credential.h"

#include <dispatch/dispatch.h>
#include <stdlib.h>
#include <string.h>
#include <xpc/xpc.h>

typedef struct {
    unsigned phase; // 0 hello, 1 one call allowed, 2 consumed
    char hello_id[PRODUCT_REQUEST_ID_LENGTH + 1];
    uint8_t nonce[PRODUCT_NONCE_LENGTH];
} peer_state;

static product_operation_guard operation_guard = PRODUCT_OPERATION_GUARD_INIT;

static void handle_message(xpc_connection_t peer, xpc_object_t message,
                           peer_state *state) {
    if (message == NULL || xpc_get_type(message) != XPC_TYPE_DICTIONARY) {
        xpc_connection_cancel(peer);
        return;
    }
    const expected_identity main_identity = product_expected_main();
    // This is the audit token on this very message, never a claimed PID/UID.
    if (!verify_xpc_sender(message, &main_identity)) {
        xpc_connection_cancel(peer);
        return;
    }
    if (state->phase == 0) {
        if (!product_xpc_parse_hello(message, state->hello_id)) {
            xpc_connection_cancel(peer);
            return;
        }
        arc4random_buf(state->nonce, sizeof(state->nonce));
        if (!product_nonce_valid(state->nonce, sizeof(state->nonce))) {
            xpc_connection_cancel(peer);
            return;
        }
        xpc_object_t ready = product_xpc_make_ready(
            message, state->hello_id, state->nonce);
        if (ready == NULL) {
            xpc_connection_cancel(peer);
            return;
        }
        state->phase = 1;
        xpc_connection_send_message(peer, ready);
        xpc_release(ready);
        return;
    }
    if (state->phase != 1) {
        xpc_connection_cancel(peer);
        return;
    }
    // Consume the connection before parsing or touching the Keychain.
    state->phase = 2;
    char request_id[PRODUCT_REQUEST_ID_LENGTH + 1] = {0};
    credential_request request = {0};
    uint8_t location[PRODUCT_LOCATION_ID_LENGTH] = {0};
    bool valid = product_xpc_parse_call(
        message, state->hello_id, state->nonce, request_id, &request, location);
    phase3_secure_zero(state->nonce, sizeof(state->nonce));
    if (!valid) {
        phase3_secure_zero(location, sizeof(location));
        xpc_connection_cancel(peer);
        return;
    }
    credential_result result;
    if (!product_operation_guard_try_acquire(&operation_guard)) {
        // Parsed, authenticated calls are consumed, but no item access is
        // queued behind a prompt that may outlive its client's timeout.
        result = (credential_result){PRODUCT_UNAVAILABLE, NULL, 0};
    } else {
        result = credential_execute(&request, &PRODUCT_NATIVE_OPS, location);
        product_operation_guard_release(&operation_guard);
    }
    phase3_secure_zero(location, sizeof(location));
    xpc_object_t reply = product_xpc_make_reply(
        message, request_id, request.operation, &result);
    credential_result_clear(&result);
    if (reply == NULL) {
        xpc_connection_cancel(peer);
        return;
    }
    xpc_connection_send_message(peer, reply);
    xpc_release(reply);
}

static void accept_connection(xpc_connection_t peer) {
    __block peer_state state = {0};
    // Per-peer state remains serial, while separate peers can receive an
    // immediate busy response during another peer's SecurityAgent prompt.
    dispatch_queue_t queue = dispatch_queue_create(
        "org.shortlink.generator.credential-peer", DISPATCH_QUEUE_SERIAL);
    if (queue == NULL) {
        xpc_connection_cancel(peer);
        return;
    }
    xpc_connection_set_target_queue(peer, queue);
    dispatch_release(queue);
    xpc_connection_set_event_handler(peer, ^(xpc_object_t event) {
        handle_message(peer, event, &state);
    });
    xpc_connection_resume(peer);
}

int main(void) {
    if (!PRODUCT_EXECUTION_ALLOWED) return 78;
    if (!phase3_prepare_process()) return 74;
    const expected_identity main_identity = product_expected_main();
    if (!identity_pin_configured(&main_identity)) return 78;
    xpc_main(accept_connection);
}
