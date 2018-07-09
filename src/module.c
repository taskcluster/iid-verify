#include "verify.h"
#include <node_api.h>
#include <stdio.h>
#include <stdlib.h>

napi_status HandleError(napi_env env, struct Error *err) {
  if (err == NULL) {
    return napi_ok;
  }
  napi_status status;
  napi_value error;       // The js Error object
  napi_value errors;      // The js list of error strings
  napi_value errorString; // Used to build the list of strings
  int size;               // used to build strings
  char *msg = NULL;       // used to build strings

  // Create an array for all of the error strings
  status = napi_create_array(env, &errors);
  if (status != napi_ok)
    return status;

#ifdef VF_DEBUG
  printf("created js array\n");
#endif

  // We're going to create the error object so that the head of the err linked
  // list is the error object's message.  This *should* be the root error
  status = napi_create_string_utf8(env, err->func, NAPI_AUTO_LENGTH,
                                   &errorString);

  if (status != napi_ok)
    return status;

#ifdef VF_DEBUG
  printf("created js string for Error.message: %s\n", err->func);
#endif

  status = napi_create_error(env, NULL, errorString, &error);
  if (status != napi_ok)
    return status;

#ifdef VF_DEBUG
  printf("created js Error\n");
#endif

  for (int i = 0; err != NULL; i++) {
    // First, create string to get size of req'd buffer
    size = snprintf(NULL, 0, "%s %s:%d %s", err->lib, err->func,
                    err->line, err->reason);

#ifdef VF_DEBUG
    printf("determined c string size for error %d: %d\n", i, size);
#endif

    // Now allocate the memory
    msg = malloc(size + 1);

    // Now print for real
    size = snprintf(msg, size, "%s %s:%d %s", err->lib, err->func,
                    err->line, err->reason);

#ifdef VF_DEBUG
    printf("determined c string for error %d: %s\n", i, msg);
#endif

    status = napi_create_string_utf8(env, msg, size - 1, &errorString);
    if (status != napi_ok)
      return status;

#ifdef VF_DEBUG
  printf("created js string for Error %d .message: %s\n", i, err->func);
#endif

    free(msg);

    // Insert the error string into the errors array
    status = napi_set_element(env, errors, i, errorString);
    if (status != napi_ok)
      return status;

    // Now, move to the next error;
    err = err->next;
  }

  status = napi_set_named_property(env, error, "errors", errors);
  if (status != napi_ok)
    return status;

#ifdef VF_DEBUG
  printf("set js object property Error.errors\n");
#endif

  VF_err_free(err);

  status = napi_throw(env, error);
  if (status != napi_ok)
    return status;
#ifdef VF_DEBUG
  printf("threw js Error\n");
#endif

  return napi_ok;
}

napi_value Call_VF_verify(napi_env env, napi_callback_info info) {
  napi_value outcome;
  napi_status status;
  size_t argc = 3;
  napi_value argv[argc];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);

  if (status != napi_ok) {
    return NULL;
  }

#ifdef VF_DEBUG
  printf("got js callback information\n");
#endif

  // Get the buffer lengths
  size_t pubkey_l;
  size_t document_l;
  size_t signature_l;

  void *pubkey;
  void *document;
  void *signature;

  status = napi_get_buffer_info(env, argv[0], &pubkey, &pubkey_l);
  if (status != napi_ok) {
    return NULL;
  }

#ifdef VF_DEBUG
  printf("got js buffer information for pubkey\n");
#endif

  status = napi_get_buffer_info(env, argv[1], &document, &document_l);
  if (status != napi_ok) {
    return NULL;
  }

#ifdef VF_DEBUG
  printf("got js buffer information for document\n");
#endif

  status = napi_get_buffer_info(env, argv[2], &signature, &signature_l);
  if (status != napi_ok) {
    return NULL;
  }

#ifdef VF_DEBUG
  printf("got js buffer information for signature\n");
#endif

  struct Error *err = NULL;
  VF_return_t result;
  result = VF_verify(pubkey, pubkey_l, document, document_l, signature,
                     signature_l, &err);

#ifdef VF_DEBUG
  printf("ran VF_verify: %s\n", result ? "true" : "false");
#endif

  switch (result) {
  case VF_FAIL:
  case VF_SUCCESS:
    status = napi_get_boolean(env, result == VF_SUCCESS, &outcome);
    if (status != napi_ok) {
      napi_throw_error(env, NULL, "error getting ref to boolean");
    }
#ifdef VF_DEBUG
    printf("got reference to js %s\n", result == VF_SUCCESS ? "true" : "false");
#endif
    break;
  default:
    status = HandleError(env, err);
    if (status != napi_ok) {
      return NULL;
    }
#ifdef VF_DEBUG
    printf("ran HandleError\n");
#endif

    status = napi_get_boolean(env, false, &outcome);
    if (status != napi_ok) {
      return NULL;
    }
#ifdef VF_DEBUG
    printf("got reference to js false for exception\n");
#endif
    break;
  }

  return outcome;
}

// Initialize our N-Api C-Side code
napi_value init(napi_env env, napi_value exports) {

  // Our verification code requires us to initialise the OpenSSL library
  // which we're built against
  if (VF_SUCCESS != VF_init()) {
    napi_throw_error(env, NULL, "Unable to initialize OpenSSL library");
  }

  napi_status status;
  napi_value fn;

  status = napi_create_function(env, NULL, 0, Call_VF_verify, NULL, &fn);
  if (status != napi_ok) {
    return NULL;
  }

  status = napi_set_named_property(env, exports, "verify", fn);
  if (status != napi_ok) {
    return NULL;
  }

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init)
