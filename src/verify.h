#ifndef VERIFY_H
#define VERIFY_H

// Store the return value of the code.  Like command line tools, a value >=1
// will be a failure and == 0 will be success.
typedef unsigned int return_t;
#define VF_SUCCESS 0
#define VF_FAIL 1

// Call this function before calling any others.  This is required to
// initialize the OpenSSL library for use in this program
return_t VF_init();

// Given a public key, a document and a PKCS#7 envelope as well as their
// respective lenghts, return VF_SUCCESS if the document signature is correct
// for the given public key
return_t VF_verify(char* pubkey,         size_t pubkey_length,
                   char* document,       size_t document_length,
                   char* pkcs7_envelope, size_t pkcs7_envelope_length);

#endif
