#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/safestack.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "./verify.h"

#ifndef BENCH_ITER
#define BENCH_ITER 100
#endif

// Set up some stdio wrappers for dumping BIO messages
BIO *bio_out, *bio_err;

// Returns the number of bytes read, and sets the contents ** to the start
// of the memory buffer
return_t read_complete_file(char *filename, char **value, long *length) {
  FILE *f = fopen(filename, "r");
  if (!f) {
    perror("opening file");
    return VF_FAIL;
  }

  if (-1 == fseek(f, 0, SEEK_END)) {
    perror("seeking to file end");
    fclose(f);
    return VF_FAIL;
  }

  long size = ftell(f);
  *length = size;

  if (-1 == fseek(f, 0, SEEK_SET)) {
    perror("seeking to beginning of file");
    fclose(f);
    return VF_FAIL;
  }

  *value = malloc(size + 1);
  if (*value == NULL) {
    perror("allocating buffer");
    fclose(f);
    return VF_FAIL;
  }

  int read = fread(*value, 1, size, f);

  if (!ferror(f) || read != size) {
    fclose(f);
    return VF_SUCCESS;
  } else {
    perror("Reading file");
    fclose(f);
    return VF_FAIL;
  }
}

// Print out a complete BIO to console, probably only safe to do on simple BIO
// types, like memory buffer backed ones
//
// NOTE: This code is only intended for testing/debugging
void print_bio_s_mem(BIO *bio, size_t len) {
  char *value = malloc(sizeof(char) * len);
  BIO_read(bio, value, len);
  BIO_write(bio_out, value, len);
  BIO_printf(bio_out, "\n");
  free(value);
}

char *memdup(char *src, long len) {
  char *x = malloc(len);
  memcpy(x, src, len);
  return x;
}

// Do some tests.  I don't care about leaking memory in this function
// so much, but I do care in the code being tested
int main(void) {
  bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
  bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);

  char *pubkey;
  long pubkey_l;
  if (VF_FAIL ==
      read_complete_file("./test-files/rsa2048-pubkey", &pubkey, &pubkey_l)) {
    BIO_printf(bio_err, "failed to read rsa2048 public key file");
    exit(1);
  }

  char *document;
  long document_l;
  if (VF_FAIL ==
      read_complete_file("./test-files/document", &document, &document_l)) {
    BIO_printf(bio_err, "failed to read clear text document");
    exit(1);
  }

  char *signature;
  long signature_l;
  // Note that we have a special version of the RSA2048 PKCS#7 document that
  // has the headers added to it.  This is something that Amazon does not
  // provide, but doing that check is significantly easier from the JS part of
  // this library
  if (VF_FAIL == read_complete_file("./test-files/rsa2048-with-header",
                                    &signature, &signature_l)) {
    BIO_printf(bio_err, "failed to read PKCS#7 signature");
  }

  char *invalid_pubkey = memdup(pubkey, pubkey_l);
  char *invalid_document = memdup(document, document_l);
  char *invalid_signature = memdup(signature, signature_l);

  invalid_pubkey[20] ^= 1;
  invalid_document[20] ^= 1;
  invalid_signature[20] ^= 1;

  VF_init();

  int pass = 0, tests = 0, outcome = VF_FAIL;
  ///////////////////////////////////////////////
  // Test a valid thing
  outcome =
      VF_verify(pubkey, pubkey_l, document, document_l, signature, signature_l);
  tests++;
  if (outcome == VF_SUCCESS) {
    pass++;
  } else {
    fprintf(stderr, "FAIL: normal case");
  }

  int failed_iterations = 0;
  struct timeval start;
  struct timeval end;
  int iter = BENCH_ITER;

  gettimeofday(&start, NULL);

  for (int i = 0; i < iter; i++) {
    outcome = VF_verify(pubkey, pubkey_l, document, document_l, signature,
                        signature_l);
    if (outcome != VF_SUCCESS) {
      failed_iterations++;
    }
  }

  gettimeofday(&end, NULL);

  long duration =
      (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;

  printf("Completed %d iterations in %0.4f seconds, %0.4fus per iteration\n",
         iter, duration / 1000000.0, duration / (double)iter);
  tests++;
  if (0 == failed_iterations) {
    pass++;
  } else {
    fprintf(stderr, "FAIL: multiple iterations");
  }

  ///////////////////////////////////////////////
  // Test an invalid document
  outcome = VF_verify(pubkey, pubkey_l, invalid_document, document_l, signature,
                      signature_l);
  tests++;
  if (outcome == VF_FAIL) {
    pass++;
  } else {
    fprintf(stderr, "FAIL: invalid document");
  }

  ///////////////////////////////////////////////
  // Test an invalid pubkey
  outcome = VF_verify(invalid_pubkey, pubkey_l, document, document_l, signature,
                      signature_l);
  tests++;
  if (outcome == VF_FAIL) {
    pass++;
  } else {
    fprintf(stderr, "FAIL: invalid pubkey");
  }

  ///////////////////////////////////////////////
  // Test an invalid signature
  outcome = VF_verify(pubkey, pubkey_l, document, document_l, invalid_signature,
                      signature_l);
  tests++;
  if (outcome == VF_FAIL) {
    pass++;
  } else {
    fprintf(stderr, "FAIL: invalid signature");
  }

  BIO_printf(bio_out, "%d tests run, %d passed\n", tests, pass);

  BIO_flush(bio_out);
  BIO_flush(bio_err);
  fflush(stdout);
  fflush(stderr);
  BIO_free(bio_out);
  BIO_free(bio_err);

  free(document);
  free(pubkey);
  free(signature);
  free(invalid_document);
  free(invalid_pubkey);
  free(invalid_signature);

  return tests - pass;
}
