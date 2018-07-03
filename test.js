const subject = require('./');
const assume = require('assume');
const fs = require('fs');

describe('verify', () => {
  let pubkey;
  let document;
  let pkcs7;
  let pkcs7_with_header;

  beforeEach(() => {
    pubkey = fs.readFileSync('./test-files/rsa2048-pubkey');
    document = fs.readFileSync('./test-files/document');
    pkcs7 = fs.readFileSync('./test-files/rsa2048');
    pkcs7_with_header = fs.readFileSync('./test-files/rsa2048-with-header');

  });

  it('should be a function', () => {
    assume(subject).is.function();
  });

  describe('with missing values', () => {
    it('should throw when no values are provided', () => {
      assume(() => {
        subject();
      }).throws(/must be provided$/);
    });
    it('should throw when pubkey isnt provided', () => {
      assume(() => {
        subject(undefined, 'y', 'z');
      }).throws(/^pubkey must be provided$/);
    });
    it('should throw when document isnt provided', () => {
      assume(() => {
        subject('x', undefined, 'z');
      }).throws(/^document must be provided$/);
    });
    it('should throw when pkcs7 isnt provided', () => {
      assume(() => {
        subject('x', 'y', undefined);
      }).throws(/^pkcs7 must be provided$/);
    });
  });

  describe('with bad values', () => {
    it('should return false with empty Buffer values', () => {
      assume(subject(Buffer.from(''), Buffer.from(''), Buffer.from(''))).is.not.ok();
    });

    it('should return false with empty string values', () => {
      assume(subject('', '', '')).is.not.ok();
    });

    it('should return false with zero-length Buffer values', () => {
      assume(subject(Buffer.of(0), Buffer.of(0), Buffer.of(0))).is.not.ok();
    });

    it('should return false with all new-line string values', () => {
      assume(subject('\n\n\n', '\n\n\n', '\n\n\n')).is.not.ok();
    });

    it('should return false with all new-line buffer values', () => {
      assume(subject(Buffer.from('\n\n\n'), Buffer.from('\n\n\n'), Buffer.from('\n\n\n'))).is.not.ok();
    });
  });

  describe('with valid files', () => {
    it('should validate valid credentials with header in buffer', () => {
      assume(subject(pubkey, document, pkcs7)).is.ok();
    });

    it('should validate valid credentials without header in buffer', () => {
      assume(subject(pubkey, document, pkcs7_with_header)).is.ok();
    });

    it('should validate valid credentials with header in string', () => {
      assume(subject(pubkey.toString(), document.toString(), pkcs7.toString())).is.ok();
    });

    it('should validate valid credentials without header in string', () => {
      assume(subject(pubkey.toString(), document.toString(), pkcs7_with_header.toString())).is.ok();
    });
  });

  // Slightly, as in off by a very small amount
  describe('with slightly invalid files', () => {
    it('should fail to validate with an extra character on document', () => {
      for (let i = 0; i <= 255; i++) {
        let badDoc = Buffer.concat([
          document,
          Buffer.from([i]),
        ]);
        assume(subject(pubkey, badDoc, pkcs7_with_header)).is.not.ok();
      }
    });

    // A bit flip on any bit of this file should generate an error.  We know this
    it('should fail for bitflips on document', () => {
      for (let i = 0; i < document.length; i++) {
        for (let j = 0; j < 8; j++) {
          let badDoc = Buffer.from(document);
          /*console.log([
            'Byte ', i,
            'Bit ', j,
            parseInt(badDoc[i], 10).toString(2),
            ' -> ',
            parseInt(badDoc[i] ^ (1 << j), 10).toString(2),
          ].join(' '))*/
          badDoc[i] ^= 1 << j;
          assume(subject(pubkey, badDoc, pkcs7_with_header)).is.not.ok();
        }
      }
    });

    // We're going to flip some bits here.  We're only going to try to flip the
    // bits that relate to the cryptographic calculations.  We don't flip all
    // bits for this document since we're not doing signature file validation
    // because of a self-signed certificate being used (i.g. -noverify)
    it('should fail for bitflips on public key data', () => {
      let pubkeydata = Buffer.from(pubkey).toString('ascii');
      pubkeydata = pubkeydata.replace(/\n/g, '');
      pubkeydata = pubkeydata.replace(/-----BEGIN CERTIFICATE-----/g, '');
      pubkeydata = pubkeydata.replace(/-----END CERTIFICATE-----/g, '');
      pubkeydata = Buffer.from(pubkeydata, 'base64');

      const rsaStart = 289 + 4; // 286 is offset, 4 is header size
      const rsaEnd = rsaStart + 257; // 257 is the size of the rsaEncryption
      for (let i = rsaStart; i < rsaEnd; i++) {
        for (let j = 0; j < 8; j++) {
          let badPubkey = Buffer.from(pubkeydata);
          badPubkey[i] ^= 1 << j;
          badPubkey = Buffer.from('-----BEGIN CERTIFICATE-----\n'
                                  + badPubkey.toString('base64')
                                  + '\n-----END CERTIFICATE-----\n');
          assume(subject(badPubkey, document, pkcs7_with_header)).is.not.ok();
        }
      }
    });

    // We're going to flip some bits here.  We're only going to try to flip the
    // bits that relate to the cryptographic calculations.  We don't flip all
    // bits for this document since we're not doing signature file validation
    // because of a self-signed certificate being used (i.g. -noverify)
    it('should fail for bitflips on signature data', () => {
      let x = new Array();
      let sigdata = Buffer.from(pkcs7).toString('ascii');
      sigdata = Buffer.from(sigdata, 'base64');

      // I got the values here by using an ASN.1 decoder to find the
      // cryptograpic parts of the signature to alter https://lapo.it/asn1js
      const mdStart = 737 + 2; // 737 is offset, 2 is header size
      const mdEnd = mdStart + 32; // 32 is the size of the messageDigest
      const rsaStart = 786 + 4; // 786 is offset, 4 is header size
      const rsaEnd = rsaStart + 256; // 256 is the size of the rsaEncryption
      for (let i = mdStart; i < rsaEnd; i++) {
        if (i > mdEnd && i < rsaStart) {
          continue;
        }
        for (let j = 0; j < 8; j++) {
          let badP7 = Buffer.from(sigdata);
          badP7[i] ^= 1 << j;
          badP7 = Buffer.from('-----BEGIN PKCS7-----\n'
                              + badP7.toString('base64')
                              + '\n-----END PKCS7-----\n');
          assume(subject(pubkey, document, badP7)).is.not.ok();
        }
      }
    });
  });
});
