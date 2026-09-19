#ifndef MERLIN_ENDPOINT_SECURITY_COMPAT_H
#define MERLIN_ENDPOINT_SECURITY_COMPAT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <EndpointSecurity/EndpointSecurity.h>

/// Copies bounded TCC metadata when the SDK exposes ES_EVENT_TYPE_NOTIFY_TCC_MODIFY.
/// Returns false on older SDKs and for non-TCC messages.
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
);

#endif
