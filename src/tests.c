#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "./verify.h"

#ifndef BENCH_ITER
#define BENCH_ITER 100
#endif

void simple_test(int *tests, int *pass, int *fail, VF_return_t expected,
                 uint8_t *pubkey, int pubkey_l, uint8_t *document,
                 int document_l, uint8_t *signature, int signature_l,
                 char *msg) {

  struct timeval start;
  struct timeval end;

  struct Error *err = NULL;

  gettimeofday(&start, NULL);

  VF_return_t outcome = VF_verify(pubkey, pubkey_l, document, document_l,
                                  signature, signature_l, &err);

  gettimeofday(&end, NULL);

  long duration =
      (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;

  printf("%ld microseconds: ", duration);

  *tests += 1;

  if (outcome == expected) {
    if (expected == VF_EXCEPTION && err == NULL) {
      *fail += 1;
      printf("FAIL: got expected outcome but expected exception and received "
             "none: %s\n",
             msg);
    } else if (expected != VF_EXCEPTION && err != NULL) {
      *fail += 1;
      printf("FAIL: got expected outcome but did not expect exception and "
             "received one: %s\n",
             msg);
      struct Error *head = err;
      while (head != NULL) {
        printf("  - %s\n", VF_err_fmt(err));
        head = head->next;
      }
    } else {
      *pass += 1;
      printf("PASS: %s\n", msg);
      struct Error *head = err;
      while (head != NULL) {
        char *exc = VF_err_fmt(head);
        printf("  - EXPECTED: %s\n", exc);
        free(exc);
        head = head->next;
      }
    }
  } else {
    *fail += 1;
    printf("FAIL: outcome did not match expectation: %s outcome: %d expected: "
           "%d\n",
           msg, outcome, expected);
  }
  VF_err_free(err);
}

VF_return_t read_complete_file(char *filename, uint8_t **value, long *length) {
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

  (*value)[size] = 0;

  if (!ferror(f) && read == size) {
    fclose(f);
    *length = size;
    return VF_SUCCESS;
  } else {
    perror("Reading file");
    fclose(f);
    free(value);
    return VF_FAIL;
  }
}

uint8_t *memdup(uint8_t *src, long len) {
  uint8_t *x = malloc(len);
  memcpy(x, src, len);
  return x;
}

int main(void) {
  struct Error *err = NULL;

  uint8_t *pubkey = NULL;
  long pubkey_l;
  if (VF_FAIL ==
      read_complete_file("./test-files/rsa2048-pubkey", &pubkey, &pubkey_l)) {
    fprintf(stderr, "failed to read rsa2048 public key file\n");
    exit(1);
  }

  uint8_t *document = NULL;
  long document_l;
  if (VF_FAIL ==
      read_complete_file("./test-files/document", &document, &document_l)) {
    fprintf(stderr, "failed to read clear text document\n");
    exit(1);
  }

  uint8_t *signature = NULL;
  long signature_l;
  // Note that there is a special version of the RSA2048 PKCS#7 document that
  // has the headers added to it.  This is something that Amazon does not
  // provide, but doing that check is significantly easier from the JS part of
  // this library
  if (VF_FAIL == read_complete_file("./test-files/rsa2048-with-header",
                                    &signature, &signature_l)) {
    fprintf(stderr, "failed to read PKCS#7 signature\n");
    exit(1);
  }

  uint8_t *incorrect_document = memdup(document, document_l);
  incorrect_document[20] ^= 1;

  uint8_t *invalid_structure = NULL;
  long invalid_structure_l;
  if (VF_FAIL == read_complete_file("./test-files/not-valid-datastructure",
                                    &invalid_structure, &invalid_structure_l)) {
    fprintf(stderr, "failed to read invalid data signature\n");
    exit(1);
  }

  uint8_t *empty_pubkey = (uint8_t *)"";
  uint8_t *empty_document = (uint8_t *)"";
  uint8_t *empty_signature = (uint8_t *)"";

  uint8_t *empty_pubkey_with_header =
      (uint8_t *)"-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n";
  uint8_t *empty_signature_with_header =
      (uint8_t *)"-----BEGIN PKCS7-----\n\n-----END PKCS7-----\n";

  VF_init();

  int fail = 0, pass = 0, tests = 0, outcome = VF_FAIL;

  // Valid Document
  simple_test(&tests, &pass, &fail, VF_SUCCESS, pubkey, pubkey_l, document,
              document_l, signature, signature_l, "valid Document");

  // Things with bitflips
  simple_test(&tests, &pass, &fail, VF_FAIL, pubkey, pubkey_l,
              incorrect_document, document_l, signature, signature_l,
              "Invalid Document");

  // Malformed things
  simple_test(&tests, &pass, &fail, VF_EXCEPTION, invalid_structure,
              invalid_structure_l, document, document_l, signature, signature_l,
              "Invalid Pubkey");
  simple_test(&tests, &pass, &fail, VF_EXCEPTION, pubkey, pubkey_l, document,
              document_l, invalid_structure, invalid_structure_l,
              "Invalid Signature");

  // Empty things
  simple_test(&tests, &pass, &fail, VF_FAIL, pubkey, pubkey_l, empty_document,
              document_l, signature, signature_l, "Empty Document");
  simple_test(&tests, &pass, &fail, VF_EXCEPTION, empty_pubkey, 1, document,
              document_l, signature, signature_l, "Empty Pubkey");
  simple_test(&tests, &pass, &fail, VF_EXCEPTION, pubkey, pubkey_l, document,
              document_l, empty_signature, 1, "Empty Signature");

  // These don't work as John Ford expects.  He thought that a certificate or
  // signature of zero length would cause OpenSSL to put an error in the error
  // queue, which would trigger VF_EXCEPTION handling, but instead OpenSSL says
  // that the verification fails, but not that it's an error.  These tests are
  // in place to ensure behaviour is not changed, but the check for empty (with
  // header) values here should be done inside the Javascript portion of this
  // library
  simple_test(&tests, &pass, &fail, VF_EXCEPTION, empty_pubkey_with_header,
              strlen((char *)empty_pubkey_with_header) + 1, document,
              document_l, signature, signature_l, "Empty Pubkey (with header)");
  simple_test(&tests, &pass, &fail, VF_EXCEPTION, pubkey, pubkey_l, document,
              document_l, empty_signature_with_header,
              strlen((char *)empty_signature_with_header) + 1,
              "Empty Signature (with header)");

  ///////////////////////////////////////////////
  // Test a valid thing many times
  int failed_iterations = 0;
  struct timeval start;
  struct timeval end;
  int iter = BENCH_ITER;

  gettimeofday(&start, NULL);

  for (int i = 0; i < iter; i++) {
    err = NULL;
    outcome = VF_verify(pubkey, pubkey_l, document, document_l, signature,
                        signature_l, &err);
    switch (outcome) {
    case VF_SUCCESS:
      break;
    case VF_EXCEPTION:
      VF_err_free(err);
    default:
      failed_iterations++;
      fprintf(stderr, "FAIL: iteration %d", i);
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
    fail++;
    fprintf(stderr, "FAIL: multiple iterations\n");
  }

  fprintf(stdout, "%d tests run, %d passed, %d failed\n", tests, pass, fail);

  free(document);
  free(pubkey);
  free(signature);
  free(incorrect_document);
  free(invalid_structure);

  if (tests <= 0 || fail > 0 || pass <= 0) {
    return 1;
  } else {
    return 0;
  }
}
