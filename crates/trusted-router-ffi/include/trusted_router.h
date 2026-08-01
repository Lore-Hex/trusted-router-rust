#ifndef TRUSTED_ROUTER_H
#define TRUSTED_ROUTER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TrClient TrClient;

typedef enum TrPlane {
  TR_PLANE_INFERENCE = 0,
  TR_PLANE_CONTROL = 1
} TrPlane;

typedef enum TrErrorCode {
  TR_ERROR_NONE = 0,
  TR_ERROR_BAD_REQUEST = 1,
  TR_ERROR_AUTHENTICATION = 2,
  TR_ERROR_PERMISSION_DENIED = 3,
  TR_ERROR_NOT_FOUND = 4,
  TR_ERROR_RATE_LIMIT = 5,
  TR_ERROR_ENDPOINT_NOT_SUPPORTED = 6,
  TR_ERROR_INTERNAL = 7,
  TR_ERROR_TRANSPORT = 8,
  TR_ERROR_TIMEOUT = 9,
  TR_ERROR_SERIALIZATION = 10,
  TR_ERROR_INVALID_CONFIGURATION = 11,
  TR_ERROR_ATTESTATION = 12,
  TR_ERROR_OAUTH = 13
} TrErrorCode;

/* Strings in a TrResult are owned by the SDK. Release the result exactly once
 * with tr_result_free. http_status is zero for errors without an HTTP response.
 */
typedef struct TrResult {
  int32_t code;
  int32_t http_status;
  char *data;
  char *error;
} TrResult;

typedef int32_t (*TrStreamCallback)(const char *event_json, void *user_data);

/* api_base_url and control_base_url may be NULL to select production defaults. */
TrClient *tr_client_new(const char *api_key, const char *api_base_url,
                        const char *control_base_url);
void tr_client_free(TrClient *client);

/* plane must be TR_PLANE_INFERENCE or TR_PLANE_CONTROL. body_json,
 * workspace_id, and idempotency_key may be NULL.
 */
TrResult tr_request_json(TrClient *client, int32_t plane, const char *method,
                         const char *path, const char *body_json,
                         const char *workspace_id,
                         const char *idempotency_key);
TrResult tr_chat_completions(TrClient *client, const char *request_json,
                             const char *workspace_id,
                             const char *idempotency_key);
TrResult tr_responses(TrClient *client, const char *request_json,
                      const char *workspace_id,
                      const char *idempotency_key);
/* The callback receives a temporary JSON string for each SSE event. Return
 * nonzero to continue or zero to cancel cleanly. Copy any data retained after
 * the callback returns.
 */
TrResult tr_stream_json(TrClient *client, const char *path,
                        const char *body_json, const char *workspace_id,
                        const char *idempotency_key,
                        TrStreamCallback callback, void *user_data);
void tr_result_free(TrResult result);

#ifdef __cplusplus
}
#endif

#endif
