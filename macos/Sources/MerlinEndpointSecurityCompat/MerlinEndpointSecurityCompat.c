#include "MerlinEndpointSecurityCompat.h"

#include <string.h>

#if defined(__MAC_OS_X_VERSION_MAX_ALLOWED) && __MAC_OS_X_VERSION_MAX_ALLOWED >= 150400
#define MERLIN_HAS_TCC_MODIFY_EVENT 1
#else
#define MERLIN_HAS_TCC_MODIFY_EVENT 0
#endif

static void copy_token(es_string_token_t token, char *destination, size_t capacity) {
    if (destination == NULL || capacity == 0) {
        return;
    }
    size_t length = token.length;
    if (length >= capacity) {
        length = capacity - 1;
    }
    if (length > 0 && token.data != NULL) {
        memcpy(destination, token.data, length);
    }
    destination[length] = '\0';
}

bool merlin_es_tcc_modify_info(
    const es_message_t *message,
    char *service,
    size_t service_capacity,
    char *identity,
    size_t identity_capacity,
    uint32_t *identity_type,
    uint32_t *update_type,
    uint32_t *right,
    uint32_t *reason
) {
#if MERLIN_HAS_TCC_MODIFY_EVENT
    if (message == NULL || message->event_type != ES_EVENT_TYPE_NOTIFY_TCC_MODIFY) {
        return false;
    }

    const es_event_tcc_modify_t *event = message->event.tcc_modify;
    copy_token(event->service, service, service_capacity);
    copy_token(event->identity, identity, identity_capacity);
    if (identity_type != NULL) {
        *identity_type = (uint32_t)event->identity_type;
    }
    if (update_type != NULL) {
        *update_type = (uint32_t)event->update_type;
    }
    if (right != NULL) {
        *right = (uint32_t)event->right;
    }
    if (reason != NULL) {
        *reason = (uint32_t)event->reason;
    }
    return true;
#else
    (void)message;
    (void)service;
    (void)service_capacity;
    (void)identity;
    (void)identity_capacity;
    (void)identity_type;
    (void)update_type;
    (void)right;
    (void)reason;
    return false;
#endif
}
