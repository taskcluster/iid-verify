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
    VF_LOG("freeing Error struct at %p\n", err);
    current = head->next;
    free(head);
    head = current;
  }
}

char *VF_err_fmt(struct Error *err) {
  int size;
  char *msg = NULL;

  size = snprintf(NULL, 0, "%s %s:%d %s", err->lib, err->func, err->line,
                  err->reason);

  if (size < 0) {
    return NULL;
  }

  msg = malloc(size + 1);
  if (msg == NULL) {
    return NULL;
  }

  size = snprintf(msg, size + 1, "%s %s:%d %s", err->lib, err->func, err->line,
                  err->reason);

  if (size < 0) {
    return NULL;
  }

  return msg;
}

VF_return_t VF_verify(uint8_t *pubkey, uint64_t pubkey_l, uint8_t *document,
                      uint64_t document_l, uint8_t *pkcs7, uint64_t pkcs7_l,
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
    VF_ERROR("error while reading pkcs#7 envelope\n");
    goto end;
  }

  store = X509_STORE_new();
  if (store == NULL) {
    rv = VF_EXCEPTION;
    VF_ERROR("error while creating certificate store\n");
    goto end;
  }

  certs = sk_X509_new_null();
  if (certs == NULL) {
    rv = VF_EXCEPTION;
    VF_ERROR("error while creating stack of certificates\n");
    goto end;
  }

  cert = PEM_read_bio_X509(bio_pubkey, NULL, NULL, NULL);
  if (cert == NULL) {
    rv = VF_EXCEPTION;
    VF_ERROR("error while reading certificate\n");
    goto end;
  }

  if (0 == sk_X509_push(certs, cert)) {
    rv = VF_EXCEPTION;
    VF_ERROR("error while inserting certificate into stack\n");
    goto end;
  }

  // NOVERIFY is set to avoid validating the certificate chain for signing.
  // Since the signatures this library is designed to verify will always be
  // self-signed, the NOVERIFY option is required for the verification to work
  if (1 == PKCS7_verify(p7, certs, store, bio_document, NULL,
                        PKCS7_NOINTERN | PKCS7_NOVERIFY)) {
    rv = VF_SUCCESS;
  } else {
    // The last error in the error queue ought to be a "signature verification"
    // error as that's the last error to emit when a document validates to
    // invalid.  In order to determine whether to treat this as VF_FAIL or
    // VF_EXCEPTION, first determine whether this error is a signature
    // verification error or not.  If it is, mark this invocation of VF_verify
    // as VF_FAIL, then clear the error queue so that if future errors occur,
    // handle them as exceptions.  This also ensures that exceptions during
    // verification are handled differently to invalid signatures
    unsigned long errorNum = ERR_peek_last_error();

    if (ERR_GET_LIB(errorNum) == ERR_LIB_PKCS7 &&
        ERR_GET_FUNC(errorNum) == PKCS7_F_PKCS7_VERIFY &&
        ERR_GET_REASON(errorNum) == PKCS7_R_SIGNATURE_FAILURE) {
      ERR_clear_error();
      rv = VF_FAIL;
    } else {
      rv = VF_EXCEPTION;
      VF_ERROR("error occured while validating signature\n");
    }
  }

end:
  if (!BIO_free(bio_document) || !BIO_free(bio_pubkey) ||
      !BIO_free(bio_pkcs7)) {
    rv = VF_EXCEPTION;
    VF_ERROR("error while freeing an OpenSSL data structure\n");
  }

  PKCS7_free(p7);
  X509_STORE_free(store);
  sk_X509_free(certs);
  X509_free(cert);

  struct Error *head = NULL;

  unsigned long errorNum = ERR_peek_error();

  if (!errorNum && rv == VF_EXCEPTION) {
    // This case is for there being an exception signaled in this file but
    // there isn't a corresponding error in the OpenSSL error queue.  Ideally,
    // we'd use ERR_put_error to insert error messages which we could use to
    // display using a single error reporting system.
    head = malloc(sizeof(struct Error));
    head->reason = "IID-Verify Exception";
    head->lib = __FILE__;
    head->func = "VF_verify";
    head->next = NULL;
    head->line = __LINE__;
    *err = head;
    VF_ERROR(
        "unknown error occured during validation, using placeholder error\n");
  } else if (errorNum && err == NULL) {
    rv = VF_EXCEPTION;
    VF_ERROR("error in error queue for VF_SUCCESS or VF_FAIL, marking "
             "VF_EXCEPTION\n");
  } else if (errorNum && err != NULL) {
    rv = VF_EXCEPTION;
    VF_ERROR("error in error queue for VF_SUCCESS or VF_FAIL, marking "
             "VF_EXCEPTION\n");
    do {
      struct Error *new = malloc(sizeof(struct Error));
      errorNum = ERR_get_error_line(&new->file, &new->line);

      // This break should *not* be needed because before this invocation, only
      // the ERR_peek_error() function has been called at that point.  There
      // shouldn't have been any removals from the error queue.  Sadly, this is
      // not the case, since the call to ERR_get_error_line here returns a
      // falsy value, which means that the error queue doesn't work as
      // documented in the man page.
      if (!errorNum) {
        free(new);
        break;
      }

      new->reason = ERR_reason_error_string(errorNum);
      new->lib = ERR_lib_error_string(errorNum);
      new->func = ERR_func_error_string(errorNum);
      new->next = head;
      head = new;
      VF_ERROR("adding new error to list: %s %s %s\n", new->lib, new->func,
               new->reason);
    } while (errorNum);
    *err = head;
  }

  return rv;
}
