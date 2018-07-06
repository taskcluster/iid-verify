#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "./verify.h"

VF_return_t VF_init() {
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  // Since none of these functions return useful error messages, per the
  // openssl wiki documentation, we're just going to return success status.
  // If this changes in future, we have the option to start failing
  return VF_SUCCESS;
}

void VF_err_free(struct Error *err) {
  struct Error *head = err;
  struct Error *current = err;
  while (head != NULL) {
    current = head->next;
    free(head);
    head = current;
  }
}

VF_return_t VF_verify(char *pubkey, uint64_t pubkey_l, char *document,
                      uint64_t document_l, char *pkcs7, uint64_t pkcs7_l,
                      struct Error **err) {
  // We want to clear the OpenSSL Error queue so that we know when we're in the
  // cleanup section, any errors we hit are the result of this invocation
  ERR_clear_error();
  VF_return_t rv;

  // First, we need to convert from C-strings into BIOs backed by memory
  BIO *bio_pubkey = BIO_new_mem_buf(pubkey, pubkey_l);
  BIO *bio_document = BIO_new_mem_buf(document, document_l);
  BIO *bio_pkcs7 = BIO_new_mem_buf(pkcs7, pkcs7_l);

  // The data structures needed for verification
  PKCS7 *p7 = NULL;
  X509_STORE *store = NULL;
  STACK_OF(X509) *certs = NULL;
  X509 *cert = NULL;

  p7 = PEM_read_bio_PKCS7(bio_pkcs7, NULL, NULL, NULL);
  if (p7 == NULL) {
    rv = VF_EXCEPTION;
    goto end;
  }

  store = X509_STORE_new();
  if (store == NULL) {
    rv = VF_EXCEPTION;
    goto end;
  }

  certs = sk_X509_new_null();
  if (certs == NULL) {
    rv = VF_EXCEPTION;
    goto end;
  }

  cert = PEM_read_bio_X509(bio_pubkey, NULL, NULL, NULL);
  if (cert == NULL) {
    rv = VF_EXCEPTION;
    goto end;
  }

  if (0 == sk_X509_push(certs, cert)) {
    rv = VF_EXCEPTION;
    goto end;
  }

  // NOVERIFY is set to avoid validating the certificate chain for signing.
  // Since the signatures this library is designed to verify will always be
  // self-signed, the NOVERIFY option is required for the verification to work
  if (1 == PKCS7_verify(p7, certs, store, bio_document, NULL,
                        PKCS7_NOINTERN | PKCS7_NOVERIFY)) {
    rv = VF_SUCCESS;
  } else {
    rv = VF_FAIL;
  }

end:
  if (!BIO_free(bio_document) || !BIO_free(bio_pubkey) ||
      !BIO_free(bio_pkcs7)) {
    rv = VF_EXCEPTION;
  }

  PKCS7_free(p7);
  X509_STORE_free(store);
  sk_X509_free(certs);
  X509_free(cert);

  struct Error *head = NULL;
  // We're going to send back the last error message so that we can throw
  // an exception, but only if we've got somewhere to put the error linked
  // list
  if (err != NULL && rv == VF_EXCEPTION) {

    struct Error *newError = NULL;
    unsigned long errorNum = ERR_peek_error();

    if (!errorNum) {
      newError->reason_string = "Unspecified exception in OpenSSL";
      newError->lib_string = "<internal>";
      newError->func_string = "<internal>";
      newError->next = head;
      newError->line = 0;
    } else {
      while (errorNum) {
        newError = malloc(sizeof(struct Error));
        newError->reason_string = ERR_reason_error_string(errorNum);
        newError->lib_string = ERR_lib_error_string(errorNum);
        newError->func_string = ERR_func_error_string(errorNum);
        newError->next = head;
        errorNum =
            ERR_get_error_line(&newError->file_string, &(newError->line));
      }
    }
    *err = head;
  }

  return rv;
}
