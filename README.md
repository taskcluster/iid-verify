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

// document is a JSON file available through the metadata service // which
contains information about the instance like instance id and // AMI used to
configure the instance
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
provided by Amazon, a cleartext copy of the instance identity document and the
`rsa2048` metadata endpoint value.  The `rsa2048` document from the metadata
service is a PKCS#7 envelope without the PEM headers (e.g. `------XXX------`).

This library can handle with and without the PEM headers for the `rsa2048`
value.

## Security Notes
This library is not a general purpose S/MIME verification tool.  It is written
with the demands of the EC2 metadata service in mind exclusively, where the
message is signed with a self-signed certificate.

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

in order to run the full unit test suite
