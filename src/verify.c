#include <stdio.h>
#include <stdlib.h>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

// Set up some stdio wrappers for dumping BIO messages
BIO *bio_out, *bio_err;

// NOTE: This function is only for testing and is not intended to be used in
// real production code!
//
// Returns the number of bytes read, and sets the contents ** to the start
// of the memory buffer
long read_complete_file(char* filename, char** value) {
  printf("Opening '%s'\n", filename);
  FILE *f = fopen(filename, "r");
  if (!f) {
    perror("Opening file");
    exit(1);
  }
  printf("File Opened\n");

  if (-1 == fseek(f, 0, SEEK_END)) {
    perror("Seeking to end of file");
    exit(1);
  }

  long size = ftell(f);
  printf("File %s is %ld bytes\n", filename, size);

  if (-1 == fseek(f, 0, SEEK_SET)) {
    perror("Seeking to beginning of file");
    exit(1);
  }

  *value = malloc(size + 1);
  if (*value == NULL) {
    perror("Allocating a buffer");
    exit(1);
  }

  int read = fread(*value, 1, size, f);

  if (!ferror(f)) {
    printf("Read %d bytes from file\n", read);
    fclose(f);
  } else {
    perror("Reading file");
    exit(1);
  }

  return size;
}

// Print out a complete BIO to console, probably only safe to do on simple BIO
// types, like memory buffer backed ones
//
// NOTE: This code is only intended for testing/debugging
void print_bio_s_mem(BIO *bio, size_t len) {
  char* value = malloc(sizeof(char) * len);
  BIO_read(bio, value, len);
  BIO_write(bio_out, value, len);
  BIO_printf(bio_out, "\n");
  free(value);
}

// Store the return value of the code.  Like command line tools, a value >=1
// will be a failure and == 0 will be success.
typedef unsigned int return_t;
#define VF_SUCCESS 0
#define VF_FAIL 1

return_t VF_init() {
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    // Since none of these functions return useful error messages, per the
    // openssl wiki documentation, we're just going to return success status.
    // If this changes in future, we have the option to start failing
    return VF_SUCCESS;
}

// Given a public key, document and a pkcs#7 envelope, and their respective
// lengths, return VF_SUCCESS iff the signatures validate, otherwise VF_FAIL
// NOTE: lengths must include the NULL byte
//
// TODO:
//  - make sure all cleanup happens all the time
//  - make sure that all return values are correct read
//  - consider using ERR_get_error (iirc) to get actual error reasons
//  - make sure we're correctly forcing FORMAT_PEM
return_t VF_verify(char* pubkey,         size_t pubkey_length,
                   char* document,       size_t document_length,
                   char* pkcs7_envelope, size_t pkcs7_envelope_length) {

  // First, we need to convert from C-strings into BIOs backed by memory
  BIO *bio_pubkey = BIO_new_mem_buf(pubkey, pubkey_length);
  BIO *bio_document = BIO_new_mem_buf(document, document_length);
  BIO *bio_pkcs7_envelope = BIO_new_mem_buf(pkcs7_envelope, pkcs7_envelope_length);

  PKCS7* p7;
  if (!PEM_read_bio_PKCS7(bio_pkcs7_envelope, &p7, 0, NULL)) {
    ERR_print_errors(bio_err);
    return VF_FAIL;
  }

  X509_STORE *store = X509_STORE_new();
  if (store == NULL) {
    ERR_print_errors(bio_err);
    return VF_FAIL;
  }

  STACK_OF(X509) *certs = sk_X509_new_null();
  if (certs == NULL) {
    ERR_print_errors(bio_err);
    return VF_FAIL;
  }

  X509 *cert = NULL;
  if (!PEM_read_bio_X509(bio_pubkey, &cert, 0, NULL)) {
    ERR_print_errors(bio_err);
    return VF_FAIL;
  }

  if (0 == sk_X509_push(certs, cert)) {
    ERR_print_errors(bio_err);
    return VF_FAIL;
  }

  if (1 == PKCS7_verify(p7, certs, store, bio_document, bio_err, PKCS7_NOINTERN|PKCS7_NOVERIFY)) {
    BIO_printf(bio_out, "verified document\n");
    return VF_SUCCESS;
  }

  // TODO: check return codes
  PKCS7_free(p7);
  X509_STORE_free(store);
  X509_free(cert);
  BIO_vfree(bio_pubkey);
  BIO_vfree(bio_document);
  BIO_vfree(bio_pkcs7_envelope);
  sk_X509_free(certs);

  ERR_print_errors(bio_err);
  return VF_FAIL;
}

int run(void) {
  bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

  char* pubkey;
  long pubkey_l = read_complete_file("./test-files/rsa2048-pubkey", &pubkey);

  char* document;
  long document_l = read_complete_file("./test-files/document", &document);

  char* signature;
  long signature_l = read_complete_file("./test-files/rsa2048-with-header", &signature);

  VF_init();

  int outcome = VF_verify(pubkey, pubkey_l,
                          document, document_l,
                          signature, signature_l);
  printf("Outcome: %d\n", outcome);
  BIO_flush(bio_out);
  BIO_flush(bio_err);

  return 0;
}

int main(void) {
  return run();
}
