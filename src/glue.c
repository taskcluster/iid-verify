#include "verify.h"
#include <node_api.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_OPENSSL_ERRORS 25

napi_status HandleError(napi_env env, struct Error *err) {
  napi_status status;
  napi_value error;       // The js Error object
  napi_value errors;      // The js list of error strings
  napi_value errorString; // Used to build the list of strings

  char *msg = NULL; // used to build strings

  if (err == NULL) {
    status =
        napi_throw_error(env, NULL, "Unknown exception verifying document");
    VF_ERROR("received a NULL Error struct pointer\n");
    return status;
  }

  status = napi_create_array(env, &errors);
  if (status != napi_ok) {
    VF_ERROR("could not create js array\n");
    return status;
  }

  // Limit to the first MAX_OPENSSL_ERRORS to guard against the case where
  // a linked list is improperly formed.  If this happens, we will stop
  // reading more errors after MAX_OPENSSL_ERRORS errors are read
  int i = 0;
  while (err != NULL) {
    if (i > MAX_OPENSSL_ERRORS) {
      VF_LOG("displaying only first %d error messages\n", MAX_OPENSSL_ERRORS);
      break;
    }

    msg = VF_err_fmt(err);

    if (msg == NULL) {
      VF_ERROR("could not format Error struct %s\n", err->reason);
      return napi_generic_failure;
    }

    status = napi_create_string_utf8(env, msg, NAPI_AUTO_LENGTH, &errorString);
    if (status != napi_ok) {
      VF_ERROR("could not create js string for openssl error: %s\n", msg);
      return status;
    }

    free(msg);
    msg = NULL;

    status = napi_set_element(env, errors, i, errorString);
    if (status != napi_ok) {
      VF_ERROR("could not set error %s as index %d on Errors.errors array");
      return status;
    }

    err = err->next;
    i++;
  }

  status = napi_create_error(env, NULL, errorString, &error);
  if (status != napi_ok) {
    VF_ERROR("could not create js Error object\n");
    return status;
  }

  status = napi_set_named_property(env, error, "errors", errors);
  if (status != napi_ok) {
    VF_ERROR("could not set js Error.errors property\n");
    return status;
  }

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
    napi_throw_error(env, NULL, "could not get callback information");
    return NULL;
  }

  // Get the buffer lengths
  size_t pubkey_l;
  size_t document_l;
  size_t signature_l;

  uint8_t *pubkey;
  uint8_t *document;
  uint8_t *signature;

  status = napi_get_buffer_info(env, argv[0], (void *)&pubkey, &pubkey_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "could not get buffer information for pubkey");
    return NULL;
  }

  status = napi_get_buffer_info(env, argv[1], (void *)&document, &document_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL,
                     "could not get buffer information for document");
    return NULL;
  }

  status = napi_get_buffer_info(env, argv[2], (void *)&signature, &signature_l);
  if (status != napi_ok) {
    napi_throw_error(env, NULL,
                     "could not get buffer information for signature");
    return NULL;
  }

  struct Error *err = NULL;
  VF_return_t result;
  result = VF_verify(pubkey, pubkey_l, document, document_l, signature,
                     signature_l, &err);

  if (result == VF_EXCEPTION) {
    status = HandleError(env, err);
    if (status != napi_ok) {
      napi_throw_error(env, NULL, "could not handle error");
      return NULL;
    }
  } else {
    status = napi_get_boolean(env, result == VF_SUCCESS, &outcome);
    if (status != napi_ok) {
      napi_throw_error(env, NULL, "could not get reference to boolean");
      return NULL;
    }
  }

  return outcome;
}

napi_value init(napi_env env, napi_value exports) {
  napi_status status;
  napi_value fn;

  // Our verification code requires us to initialise the OpenSSL library
  // which we're built against
  if (VF_SUCCESS != VF_init()) {
    napi_throw_error(env, NULL, "Unable to initialize OpenSSL library");
    return NULL;
  }

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
