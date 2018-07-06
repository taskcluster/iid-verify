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

  // We're going to create the error object so that the head of the err linked
  // list is the error object's message.  This *should* be the root error
  status = napi_create_string_utf8(env, err->func_string, NAPI_AUTO_LENGTH,
                                   &errorString);
  if (status != napi_ok)
    return status;
  status = napi_create_error(env, NULL, errorString, &error);
  if (status != napi_ok)
    return status;

  for (int i = 0; err != NULL; i++) {
    // Create the error string

    // First, create string to get size of req'd buffer
    size = snprintf(NULL, 0, "%s %s:%d %s", err->lib_string, err->func_string,
                    err->line, err->reason_string);

    // Now allocate the memory
    msg = malloc(size + 1);

    // Now print for real
    size = snprintf(msg, size, "%s %s:%d %s", err->lib_string, err->func_string,
                    err->line, err->reason_string);

    status = napi_create_string_utf8(env, msg, size - 1, &errorString);
    if (status != napi_ok)
      return status;

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

  VF_err_free(err);
  return napi_throw(env, error);
}

napi_value Call_VF_verify(napi_env env, napi_callback_info info) {
  napi_value outcome;
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
  VF_return_t result;
  result = VF_verify(pubkey, pubkey_l, document, document_l, signature,
                     signature_l, &err);

  switch (result) {
  case VF_FAIL:
  case VF_SUCCESS:
    status = napi_get_boolean(env, result == VF_SUCCESS, &outcome);
    if (status != napi_ok) {
      napi_throw_error(env, NULL, "error getting ref to boolean");
    }
    break;
  default:
    status = HandleError(env, err);
    if (status != napi_ok) {
      napi_throw_error(env, NULL, "error handling error (ha!)");
    }
    break;
  }

  // All errors in a given thread's error queue are read into the linked list
  // pointed at by err.  Currently, only the first error is read here and
  // converted into a throwable JS Error.  In the future, all errors in the
  // linked list ought to be read, stored in a list, that list attached to an
  // Error and that error thrown with a useful error message.
  /*if (err != NULL) {
    char errMsg[256];
    if (!snprintf(errMsg, 256, "%s@%d#%s: %s", err->file_string, err->line,
                  err->func_string, err->reason_string)) {
      napi_throw_error(env, NULL, "trying to create error string");
    }
    napi_throw_error(env, NULL, errMsg);
  }*/

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
  if (VF_SUCCESS != VF_init()) {
    napi_throw_error(env, NULL, "Unable to initialize OpenSSL library");
  }

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
