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
module.exports = function verify(pubkey, document, pkcs7_envelope) {
  if (typeof pubkey === 'undefined') {
    throw new Error('pubkey must be provided');
  }

  if (typeof document === 'undefined') {
    throw new Error('document must be provided');
  }

  if (typeof pkcs7_envelope === 'undefined') {
    throw new Error('pkcs7_envelope must be provided');
  }

  if (!Buffer.isBuffer(pubkey)) {
    pubkey = Buffer.from(pubkey, 'utf-8');
  }

  if (!Buffer.isBuffer(document)) {
    document = Buffer.from(document, 'utf-8');
  }

  if (!Buffer.isBuffer(pkcs7_envelope)) {
    pkcs7_envelope = Buffer.from(pkcs7_envelope, 'utf-8');
  }

  // TODO: handle the case where pkcs7 doens't have a header
  hasHeader = true;
  for (let i = 0; i < pkcs7_header.length && hasHeader; i++) {
    if (pkcs7_envelope[i] !== pkcs7_header[i]) {
      hasHeader = false;
    }
  }

  // If the document has a header, we're going to assume that it's totally
  // valid and ready to pass into the verification routines, if not, we'll
  // trim any leading and trailing newlines so that the headers are valid
  if (!hasHeader) {
    while (pkcs7_envelope.length > 0 && pkcs7_envelope.indexOf(nl) === 0) {
      pkcs7_envelope = pkcs7_envelope.slice(1);
    }

    while (pkcs7_envelope.length > 0 && pkcs7_envelope.lastIndexOf(nl) === pkcs7_envelope.length - 1) {
      pkcs7_envelope = pkcs7_envelope.slice(0, pkcs7_envelope.length - 1);
    }

    pkcs7_envelope = Buffer.concat([
      pkcs7_header,
      pkcs7_envelope,
      pkcs7_footer,
    ]);
  }

  return addon.verify(
    pubkey, pubkey.length,
    document, document.length,
    pkcs7_envelope, pkcs7_envelope.length);
}
