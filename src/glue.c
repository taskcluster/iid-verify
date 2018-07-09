#include "verify.h"
#include <node_api.h>
#include <stdio.h>
#include <stdlib.h>

//#define VF_DEBUG 1

napi_status HandleError(napi_env env, struct Error *err) {
  napi_status status;
  napi_value error;       // The js Error object
  napi_value errors;      // The js list of error strings
  napi_value errorString; // Used to build the list of strings

  char *msg = NULL; // used to build strings

  if (err == NULL) {
    status =
        napi_throw_error(env, NULL, "Unknown exception verifying document");
    return status;
  }

  // Create an array for all of the error strings
  status = napi_create_array(env, &errors);
  if (status != napi_ok)
    return status;

#ifdef VF_DEBUG
  printf("created js array\n");
#endif

  // We're going to create the error object so that the head of the err linked
  // list is the error object's message.  This *should* be the root error
  msg = VF_err_fmt(err);
  status = napi_create_string_utf8(env, msg, NAPI_AUTO_LENGTH, &errorString);
#ifdef VF_DEBUG
  printf("created js string for Error.message: %s\n", msg);
#endif
  free(msg);
  msg = NULL;

  if (status != napi_ok)
    return status;

  status = napi_create_error(env, NULL, errorString, &error);
  if (status != napi_ok)
    return status;

#ifdef VF_DEBUG
  printf("created js Error\n");
#endif

  // We're limiting to the first 1000 so that we don't
  // cause an infinite loop
  int i = 0;
  while (err != NULL) {
    i++;
    if (i > 10) {
      break;
    }
    // Now allocate the memory
    msg = VF_err_fmt(err);

    status = napi_create_string_utf8(env, msg, NAPI_AUTO_LENGTH, &errorString);
    if (status != napi_ok)
      return status;

#ifdef VF_DEBUG
    printf("created js string for error string %d: %s\n", i, msg);
#endif

    free(msg);
    msg = NULL;

    // Insert the error string into the errors array
    status = napi_set_element(env, errors, i, errorString);
    if (status != napi_ok)
      return status;
    err = err->next;
  }

  status = napi_set_named_property(env, error, "errors", errors);
  if (status != napi_ok)
    return status;

#ifdef VF_DEBUG
  printf("set js object property Error.errors\n");
#endif

  VF_err_free(err);

  return napi_throw(env, error);
}

napi_value Call_VF_verify(napi_env env, napi_callback_info info) {
  napi_value outcome = NULL;
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

  uint8_t *pubkey;
  uint8_t *document;
  uint8_t *signature;

  status = napi_get_buffer_info(env, argv[0], (void*) &pubkey, &pubkey_l);
  if (status != napi_ok) {
    return NULL;
  }

#ifdef VF_DEBUG
  printf("got js buffer information for pubkey\n");
#endif

  status = napi_get_buffer_info(env, argv[1], (void*) &document, &document_l);
  if (status != napi_ok) {
    return NULL;
  }

#ifdef VF_DEBUG
  printf("got js buffer information for document\n");
#endif

  status = napi_get_buffer_info(env, argv[2], (void*) &signature, &signature_l);
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
  printf("VF_verify is success: %s\n", result == VF_SUCCESS ? "true" : "false");
  printf("VF_verify is exception: %s\n",
         result == VF_EXCEPTION ? "true" : "false");
#endif

  if (result == VF_EXCEPTION) {
    status = HandleError(env, err);
    if (status != napi_ok) {
      return NULL;
    }
#ifdef VF_DEBUG
    printf("ran HandleError because of exception\n");
#endif
  } else {
    status = napi_get_boolean(env, result == VF_SUCCESS, &outcome);
    if (status != napi_ok) {
      return NULL;
    }
#ifdef VF_DEBUG
    printf("got reference to js %s\n", result == VF_SUCCESS ? "true" : "false");
#endif
  }

  return outcome;
}

// Initialize our N-Api C-Side code
napi_value init(napi_env env, napi_value exports) {

  // Our verification code requires us to initialise the OpenSSL library
  // which we're built against
  if (VF_SUCCESS != VF_init()) {
    napi_throw_error(env, NULL, "Unable to initialize OpenSSL library");
    return NULL;
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
