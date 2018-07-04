#include "verify.h"
#include <node_api.h>
#include <stdio.h>

napi_value Call_VF_verify(napi_env env, napi_callback_info info) {
  napi_status status;
  size_t argc = 6;
  napi_value argv[argc];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Failed to parse arguments");
  }

  // Get the buffer lengths
  size_t pubkey_l;
  size_t document_l;
  size_t signature_l;

  void *pubkey;
  void *document;
  void *signature;

  status = napi_get_buffer_info(env, argv[0], &pubkey, &pubkey_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL,
                     "failed to get information about pubkey buffer");
  }
  status = napi_get_buffer_info(env, argv[1], &document, &document_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL,
                     "failed to get information about document buffer");
  }
  status = napi_get_buffer_info(env, argv[2], &signature, &signature_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL,
                     "failed to get information about signature buffer");
  }

  struct Error *err = NULL;
  return_t result;
  result = VF_verify(pubkey, pubkey_l, document, document_l, signature,
                     signature_l, &err);

  // We should read all of these at some point, and maybe even
  // give them all the information in the error nodes
  if (err != NULL) {
    char errMsg[256];
    if (!snprintf(errMsg, 256, "%s@%d#%s: %s", err->file_string, err->line,
                  err->func_string, err->reason_string)) {
      napi_throw_error(env, NULL, "trying to create error string");
    }
    napi_throw_error(env, NULL, errMsg);
  }

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
