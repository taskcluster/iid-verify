#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "./verify.h"

#ifndef BENCH_ITER
#define BENCH_ITER 100
#endif

void simple_test(int *tests, int *pass, int *fail, VF_return_t expected, char*
    pubkey, int pubkey_l, char* document, int document_l, char* signature, int
    signature_l, char* msg) {

  struct timeval start;
  struct timeval end;

  struct Error *err = NULL;

  gettimeofday(&start, NULL);

  VF_return_t outcome = VF_verify(pubkey, pubkey_l, document, document_l, signature,
      signature_l, &err);

  gettimeofday(&end, NULL);

  long duration =
      (end.tv_sec - start.tv_sec) * 1000000 + end.tv_usec - start.tv_usec;

  printf("%ld microseconds: ", duration);

  *tests += 1;

  if (outcome == expected) {
    if (expected == VF_EXCEPTION && err != NULL) {
      *fail += 1;
      printf("FAIL: expected exception, received none: %s\n", msg);
    } else if (expected != VF_EXCEPTION && err != NULL) {
      *fail += 1;
      printf("FAIL: did not expect exception, received one: %s\n", msg);
    } else {
      *pass += 1;
      printf("PASS: %s\n", msg);
    }
  } else {
    *fail += 1;
    printf("FAIL: outcome did not match expectation: %s outcome: %d expected: %d\n", msg, outcome, expected);
  }

}


// Returns the number of bytes read, and sets the contents ** to the start
// of the memory buffer
VF_return_t read_complete_file(char *filename, char **value, long *length) {
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

char *memdup(char *src, long len) {
  char *x = malloc(len);
  memcpy(x, src, len);
  return x;
}

// Do some tests.  I don't care about leaking memory in this function
// so much, but I do care in the code being tested
int main(void) {
  struct Error *err = NULL;

  char *pubkey = NULL;
  long pubkey_l;
  if (VF_FAIL ==
      read_complete_file("./test-files/rsa2048-pubkey", &pubkey, &pubkey_l)) {
    fprintf(stderr, "failed to read rsa2048 public key file\n");
    exit(1);
  }

  char *document = NULL;
  long document_l;
  if (VF_FAIL ==
      read_complete_file("./test-files/document", &document, &document_l)) {
    fprintf(stderr, "failed to read clear text document\n");
    exit(1);
  }

  char *signature = NULL;
  long signature_l;
  // Note that we have a special version of the RSA2048 PKCS#7 document that
  // has the headers added to it.  This is something that Amazon does not
  // provide, but doing that check is significantly easier from the JS part of
  // this library
  if (VF_FAIL == read_complete_file("./test-files/rsa2048-with-header",
                                    &signature, &signature_l)) {
    fprintf(stderr, "failed to read PKCS#7 signature\n");
    exit(1);
  }

  char *incorrect_document = memdup(document, document_l);
  incorrect_document[20] ^= 1;

  //char *invalid_pubkey = memdup(pubkey, pubkey_l);
  char *invalid_structure = NULL;
  long invalid_structure_l;
  if (VF_FAIL == read_complete_file("./test-files/not-valid-datastructure",
                                    &invalid_structure, &invalid_structure_l)) {
    fprintf(stderr, "failed to read invalid data signature\n");
    exit(1);
  }

  char *empty_pubkey = "";
  char *empty_document = "";
  char *empty_signature = "";

  VF_init();

  int fail = 0, pass = 0, tests = 0, outcome = VF_FAIL;

  // Valid Document
  simple_test(&tests, &pass, &fail, VF_SUCCESS, pubkey, pubkey_l, document, document_l, signature, signature_l, "valid Document");

  // Things with bitflips
  simple_test(&tests, &pass, &fail, VF_FAIL, pubkey, pubkey_l, incorrect_document, document_l, signature, signature_l, "Invalid Document");

  // Malformed things
  simple_test(&tests, &pass, &fail, VF_EXCEPTION, invalid_structure, invalid_structure_l, document, document_l, signature, signature_l, "Invalid Pubkey");
  simple_test(&tests, &pass, &fail, VF_EXCEPTION, pubkey, pubkey_l, document, document_l, invalid_structure, invalid_structure_l, "Invalid Signature");

  // Empty things
  simple_test(&tests, &pass, &fail, VF_FAIL, pubkey, pubkey_l, empty_document, document_l, signature, signature_l, "Invalid Document");
  simple_test(&tests, &pass, &fail, VF_EXCEPTION, empty_pubkey, pubkey_l, document, document_l, signature, signature_l, "Invalid Pubkey");
  simple_test(&tests, &pass, &fail, VF_EXCEPTION, pubkey, pubkey_l, document, document_l, empty_signature, signature_l, "Invalid Signature");

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
