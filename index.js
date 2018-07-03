const addon = require('bindings')('module');

const pkcs7_header = Buffer.from('-----BEGIN PKCS7-----\n');
const pkcs7_footer = Buffer.from('\n-----END PKCS7-----\n');
const nl = '\n'.charAt(0);

/**
 * Verify a document given a public key, document and a PKCS#7 encoded
 * signature.  All parameters should either be strings, Buffers or something
 * which can be converted into a Buffer safely with a call to Buffer.from(),
 * with an encoding parameter of 'utf-8'.
 */
module.exports = function verify(pubkey, document, pkcs7) {
  if (typeof pubkey === 'undefined') {
    throw new Error('pubkey must be provided');
  }

  if (typeof document === 'undefined') {
    throw new Error('document must be provided');
  }

  if (typeof pkcs7 === 'undefined') {
    throw new Error('pkcs7 must be provided');
  }

  if (!Buffer.isBuffer(pubkey)) {
    pubkey = Buffer.from(pubkey, 'utf-8');
  }

  if (!Buffer.isBuffer(document)) {
    document = Buffer.from(document, 'utf-8');
  }

  if (!Buffer.isBuffer(pkcs7)) {
    pkcs7 = Buffer.from(pkcs7, 'utf-8');
  }

  hasHeader = true;
  for (let i = 0; i < pkcs7_header.length && hasHeader; i++) {
    if (pkcs7[i] !== pkcs7_header[i]) {
      hasHeader = false;
    }
  }

  // If the document has a header, we're going to assume that it's totally
  // valid and ready to pass into the verification routines, if not, we'll
  // trim any leading and trailing newlines so that the headers are valid
  if (!hasHeader) {
    while (pkcs7.length > 0 && pkcs7.indexOf(nl) === 0) {
      pkcs7 = pkcs7.slice(1);
    }

    while (pkcs7.length > 0 && pkcs7.lastIndexOf(nl) === pkcs7.length - 1) {
      pkcs7 = pkcs7.slice(0, pkcs7.length - 1);
    }

    pkcs7 = Buffer.concat([
      pkcs7_header,
      pkcs7,
      pkcs7_footer,
    ]);
  }

  return addon.verify(
    pubkey, pubkey.length,
    document, document.length,
    pkcs7, pkcs7.length);
};
