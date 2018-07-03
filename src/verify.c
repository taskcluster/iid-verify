#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

#include "./verify.h"

return_t VF_init() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    // Since none of these functions return useful error messages, per the
    // openssl wiki documentation, we're just going to return success status.
    // If this changes in future, we have the option to start failing
    return VF_SUCCESS;
}

// TODO:
//  - make sure all cleanup happens all the time
//  - make sure that all return values are correct read
//  - consider using ERR_get_error (iirc) to get actual error reasons
//  - make sure we're correctly forcing FORMAT_PEM
return_t VF_verify(char* pubkey,   uint64_t pubkey_length,
                   char* document, uint64_t document_length,
                   char* pkcs7,    uint64_t pkcs7_length) {
  return_t rv = VF_FAIL;

  // First, we need to convert from C-strings into BIOs backed by memory
  BIO *bio_pubkey = BIO_new_mem_buf(pubkey, pubkey_length);
  BIO *bio_document = BIO_new_mem_buf(document, document_length);
  BIO *bio_pkcs7 = BIO_new_mem_buf(pkcs7, pkcs7_length);

  // We don't want the BIO_close method here to free() the memory passed in
  //BIO_set_close(bio_pubkey, BIO_NOCLOSE);
  //BIO_set_close(bio_document, BIO_NOCLOSE);
  //BIO_set_close(bio_pkcs7, BIO_NOCLOSE);

  // The data structures needed for verification
  PKCS7* p7;
  X509_STORE *store = NULL;
  STACK_OF(X509) *certs = NULL;
  X509 *cert = NULL;

  // I'd prefer to pass an out parameter, but it seems that the second time
  // that this function executes, we get a segfault in the underlying library.
  // I'm not sure how best to debug this, but using the pointer returning
  // option of the function works well
  //
  //   if(!PEM_read_bio_PKCS7(bio_pkcs7, &p7, NULL, NULL)) {
  //
  p7 = PEM_read_bio_PKCS7(bio_pkcs7, NULL, NULL, NULL);
  if (p7 == NULL) {
    rv = VF_FAIL;
    goto end;
  }

  store = X509_STORE_new();
  if (store == NULL) {
    rv = VF_FAIL;
    goto end;
  }

  certs = sk_X509_new_null();
  if (certs == NULL) {
    rv = VF_FAIL;
    goto end;
  }

  // Same as reading the PKCS#7 file above
  //   if (!PEM_read_bio_X509(bio_pubkey, &cert, 0, NULL)) {
  cert = PEM_read_bio_X509(bio_pubkey, NULL, NULL, NULL);
  if (cert == NULL) {
    rv = VF_FAIL;
    goto end;
  }

  if (0 == sk_X509_push(certs, cert)) {
    rv = VF_FAIL;
    goto end;
  }

  if (1 == PKCS7_verify(p7, certs, store, bio_document, NULL, PKCS7_NOINTERN|PKCS7_NOVERIFY)) {
    rv = VF_SUCCESS;
  }

end:
  if (!BIO_free(bio_document) || !BIO_free(bio_pubkey) || !BIO_free(bio_pkcs7)) {
    rv = VF_FAIL;
  }

  PKCS7_free(p7);
  X509_STORE_free(store);
  sk_X509_free(certs);
  X509_free(cert);
  return rv;
}

