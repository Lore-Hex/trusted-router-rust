#include "trusted_router.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  const char *key = getenv("TRUSTEDROUTER_API_KEY");
  TrClient *client = tr_client_new(key, NULL, NULL);
  if (client == NULL) {
    fputs("Could not create TrustedRouter client\n", stderr);
    return 1;
  }
  const char *request =
      "{\"model\":\"trustedrouter/auto\",\"messages\":[{\"role\":\"user\","
      "\"content\":\"Reply with PONG\"}]}";
  TrResult result = tr_chat_completions(client, request, NULL, NULL);
  if (result.code == 0) {
    puts(result.data);
  } else {
    fprintf(stderr, "HTTP %d: %s\n", result.http_status, result.error);
  }
  tr_result_free(result);
  tr_client_free(client);
  return 0;
}
