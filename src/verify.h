#ifndef VERIFY_H
#define VERIFY_H
#include <stdint.h>

// Store the return value of the code.  Like command line tools, a value >=1
// will be a failure and == 0 will be success.
typedef unsigned int VF_return_t;
#define VF_SUCCESS 0
#define VF_FAIL 1
#define VF_EXCEPTION 2

struct Error {
  const char *reason;
  const char *lib;
  const char *func;
  const char *file;
  int line;
  struct Error *next;
};

// Call this function before calling any others.  This is required to
// initialize the OpenSSL library for use in this program
VF_return_t VF_init();

// Calls to the VF_verify function which pass a non-NULL value for the Error
// struct pointer pointer will allocate heap memory to store the structures in
// the linked list.  This function must be called on the value with the Error
// struct pointer used for the VF_verify call to ensure the allocated memory is
// freed
void VF_err_free(struct Error *err);

// Verify an instance identity document.  The three required parts are the
// public key, cleartext document and the signature in a PKCS#7 file.  The
// PKCS#7 file must have the PEM headers already.  Each of these documents is
// pass in as a pointer to a memory buffer and the length of the buffer.
//
// If there are errors encountered during the invocation, they will be stored
// in the **errors list, along with the number of errors in the errors_n
// parameter.  This memory is allocated in the VF_verify function but is owned
// by the caller, which is responsible for freeing it
VF_return_t VF_verify(char *pubkey, uint64_t pubkey_l, char *document,
                      uint64_t document_l, char *pkcs7, uint64_t pkcs7_l,
                      struct Error **err);

#endif
