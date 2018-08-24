# Amazon EC2 Instance Identity Document Verification
This is a small node module written in C using N-API and the OpenSSL C API to
perform instance identity document verification.

# Usage
This library has a very simple interface:

```javascript
let fs = require('fs');
let verify = require('iid-verify');

// http://169.254.169.254/latest/dynamic/instance-identity/{rsa2048, document}
// Public key provided by Amazon

// document is a JSON file available through the metadata service which
// contains information about the instance like instance id and AMI used to
// configure the instance
let document = fs.readFileSync('document');

// rsa2048 is a PCKS#7 envelope which contains the cryptographic signature
// of the document computed against the Amazon EC2 private key.  We strongly
// suggest using the rsa2048 enpoint instead of the pkcs7 endpoint because
// the rsa2048 endpoint uses SHA256 instead of the pkcs7 endpoint's SHA1
let rsa2048 = fs.readFileSync('rsa2048');

// pubkey is a PEM encoded public key as provided by Amazon EC2.  This
// public key is unique to each region and each account and so must be
// obtained by requesting in a service ticket
let pubkey = fs.readFileSync('pubkey');

if (verify(pubkey, document, rsa2048)){
  console.log('This document is valid!');
} else {
  console.log('CAUTION: This document is INVALID!');
}
```

# API
There is a single function in this library: `verify`.  It takes a public key as
provided by Amazon, a clear text copy of the instance identity document and the
`rsa2048` metadata endpoint value.  The `rsa2048` document from the metadata
service is a PKCS#7 envelope without the PEM headers (e.g. `------XXX------`).

This library can handle with and without the PEM headers for the `pkcs7`
argument.

# Errors
The `verify` function of this library has three expected outcomes:

1. Document validates against signature and public key -- instance identity
   document is valid and trustworthy.  `verify` returns true.
2. Document does not validate against signature -- instance identity document,
   public key or pkcs7 signature is not correct.  `verify` returns false.
3. A javascript `Error` is thrown from the library along with information about
   which error occurred.

It's important to note that an exception being thrown does not imply that the
document is valid or invalid.  The document's validity is only know if the
function returns either `true` or `false`.

An error which is thrown by this library could either be a simple error from
the Javascript library for something like a required parameter being `undefined`
or it could be an error from the OpenSSL library.

Errors which are sent from OpenSSL are Javascript `Error` objects.  The `.message`
property for these `Error` objects is the root-most cause of the error, however,
all OpenSSL errors which occurred during the invocation of `verify` are included
as a list of strings in the `.errors` property.

Here's an example of an error which occurs when a public key which is not in the
correct format is specified.  This is Javascript code meant to illustrate how the
exception is thrown.  The actual exception is thrown by the `src/glue.c`:`HandleError`
function in the N-API C portion of the library.

```javascript
let err = new Error('asn1 encoding routines ../deps/openssl/openssl/crypto/asn1/asn1_lib.c:157 ASN1_get_object header too long');
err.errors = [
     'PEM routines ../deps/openssl/openssl/crypto/pem/pem_oth.c:83 PEM_ASN1_read_bio ASN1 lib',
     'asn1 encoding routines ../deps/openssl/openssl/crypto/asn1/tasn_dec.c:374 ASN1_ITEM_EX_D2I nested asn1 error',
     'asn1 encoding routines ../deps/openssl/openssl/crypto/asn1/tasn_dec.c:1188 ASN1_CHECK_TLEN bad object header',
     'asn1 encoding routines ../deps/openssl/openssl/crypto/asn1/asn1_lib.c:157 ASN1_get_object header too long'
];
throw err;
```

The order of the list is that the highest level error comes first and the
root-most error comes last

## Security Notes
This library is not a general purpose S/MIME verification tool.  It is written
with the demands of the EC2 metadata service in mind exclusively, where the
message is signed with a self-signed certificate.  Because of this, there is a
`NOVERIFY` option in the code.  This does not disable signature verification,
rather, it disables certificate chain validation.  Since we're providing the
only acceptable public key directly, we cannot do this chain validation.

# Developing
You'll need Linux.  Other systems might work, but are completely untested.

This module will try to link against the OpenSSL distributed with your Node
installation, but will fallback to using the system's OpenSSL library.  This
module makes no attempt to build or package a copy of OpenSSL, so please ensure
that you have a system installation.

You should be able to build and test this module with `yarn test`.  NPM is
untested.  This only tests the JS portion of the module, so if you're working
on any of the C portions, or you're changing out they talk to each other,
you'll need to also run `yarn run other-tests`.

The other tests include running with ElectricFence and Valgrind.  There should
be no memory leaks from this library.

You will need:

  * clang
  * clang-format
  * valgrind
  * electric-fence

In order to run the full unit test suite

On Ubuntu, try:
```
sudo apt-get install clang clang-format electric-fence valgrind
```

On Fedora, try:
```
sudo dnf install clang valgrind ElectricFence
```
