#include "verify.h"
#include <node_api.h>

napi_value Call_VF_verify(napi_env env, napi_callback_info info) {
  napi_status status;
  size_t argc = 6;
  napi_value argv[argc];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Failed to parse arguments");
  }

  // Get the buffer lengths
  uint64_t pubkey_l;
  uint64_t document_l;
  uint64_t signature_l;
  status = napi_get_value_int64(env, argv[1], (int64_t *)&pubkey_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "failed to read pubkey length");
  }
  status = napi_get_value_int64(env, argv[3], (int64_t *)&document_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "failed to read document length");
  }
  status = napi_get_value_int64(env, argv[5], (int64_t *)&signature_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "failed to read signature length");
  }

  void *pubkey;
  void *document;
  void *signature;

  status = napi_get_buffer_info(env, argv[0], &pubkey, (size_t *)&pubkey_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL,
                     "failed to get information about pubkey buffer");
  }
  status = napi_get_buffer_info(env, argv[2], &document, (size_t *)&document_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL,
                     "failed to get information about document buffer");
  }
  status =
      napi_get_buffer_info(env, argv[4], &signature, (size_t *)&signature_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL,
                     "failed to get information about signature buffer");
  }

  return_t result;
  result =
      VF_verify(pubkey, pubkey_l, document, document_l, signature, signature_l);

  napi_value outcome;
  status = napi_get_boolean(env, result == VF_SUCCESS, &outcome);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to create return value");
  }

  return outcome;
}

// Initialize our N-Api C-Side code
napi_value init(napi_env env, napi_value exports) {

  // Our verification code requires us to initialise the OpenSSL library
  // which we're built against
  VF_init();

  napi_status status;
  napi_value fn;

  status = napi_create_function(env, NULL, 0, Call_VF_verify, NULL, &fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to create function");
  }

  status = napi_set_named_property(env, exports, "verify", fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
