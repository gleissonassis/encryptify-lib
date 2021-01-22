const chai = require('chai');
const { expect } = chai;
const { IdentityHelper } = require('../../src/index');

describe('IdentityHelper', () => {
  const commonIdentity = {
    address: '0x3f243FdacE01Cfd9719f7359c94BA11361f32471',
    privateKey:
      '0x107be946709e41b7895eea9f2dacf998a0a9124acbb786f0fd1a826101581a07',
    publicKey:
      'bf1cc3154424dc22191941d9f4f50b063a2b663a2337e5548abea633c1d06eceacf2b81dd326d278cd992d5e03b0df140f2df389ac9a1c2415a220a4a9e8c046',
    compressedPublicKey:
      '02bf1cc3154424dc22191941d9f4f50b063a2b663a2337e5548abea633c1d06ece',
  };

  it('should generate a new identity', async () => {
    const identity = await IdentityHelper.generateIdentity();

    expect(identity).to.have.property('privateKey');
    expect(identity).to.have.property('publicKey');
    expect(identity).to.have.property('compressedPublicKey');
    expect(identity).to.have.property('address');
  });

  it('should generate an identity based on a private key', async () => {
    const originalIdentity = await IdentityHelper.generateIdentity();
    const identity = await IdentityHelper.generateIdentity(
      originalIdentity.privateKey
    );

    expect(identity.privateKey).to.equal(identity.privateKey);
    expect(identity.publicKey).to.equal(identity.publicKey);
    expect(identity.compressedPublicKey).to.equal(identity.compressedPublicKey);
    expect(identity.address).to.equal(identity.address);
  });

  it('should encrypt and decrypt data using a simetrict key', async () => {
    const data = 'info';
    const key = 'key';

    expect(data).to.be.equal(
      IdentityHelper.decrypt(key, IdentityHelper.encrypt(key, data))
    );
  });

  it('should generate a valid hash from text', () => {
    const data = 'info';

    const hash = IdentityHelper.generateHash(data);

    expect(hash).to.be.equal(
      '06271baf49532c879aa3c58b48671884bcc858f09197412d682750496c33e1e1'
    );
  });

  it('should compress a public key', () => {
    expect(
      IdentityHelper.compressPublicKey(commonIdentity.publicKey)
    ).to.be.equal(
      '02bf1cc3154424dc22191941d9f4f50b063a2b663a2337e5548abea633c1d06ece'
    );
  });

  it('should return true to a compressed publicKey', () => {
    const compressedPublicKey =
      '02bf1cc3154424dc22191941d9f4f50b063a2b663a2337e5548abea633c1d06ece';
    expect(IdentityHelper.isCompressedPublicKey(compressedPublicKey)).to.be
      .true;
  });

  it('should return false to an uncompressed publicKey', () => {
    const uncompressedPublicKey =
      'bf1cc3154424dc22191941d9f4f50b063a2b663a2337e5548abea633c1d06eceacf2b81dd326d278cd992d5e03b0df140f2df389ac9a1c2415a220a4a9e8c046';
    expect(IdentityHelper.isCompressedPublicKey(uncompressedPublicKey)).to.be
      .false;
  });

  it('should sign a hashed message with the private key', () => {
    const messageg = 'info';
    const hash = IdentityHelper.generateHash(messageg);
    const signature = IdentityHelper.sign(commonIdentity.privateKey, hash);

    expect(signature).to.be.equal(
      '0xa3468121547bf3083fd7d500fb56c3787462b6a56893cca43219f7e78331351140950f752d7cf32374782043708e9cfd4dd4cf6d5fa5397d9f1523e6f2fef77f1c'
    );
  });

  it('should recover the address from a signature and the original hash', async () => {
    const identity = await IdentityHelper.generateIdentity();

    const messageg = 'info';
    const hash = IdentityHelper.generateHash(messageg);
    const signature = IdentityHelper.sign(identity.privateKey, hash);
    const address = IdentityHelper.recoverAddress(signature, hash);

    const originalAddress = identity.address;

    expect(address).to.be.equal(originalAddress);
  });

  it('should recover the public key from a signature and the original hash', async () => {
    const identity = await IdentityHelper.generateIdentity();

    const messageg = 'info';
    const hash = IdentityHelper.generateHash(messageg);
    const signature = IdentityHelper.sign(identity.privateKey, hash);
    const publicKey = IdentityHelper.recoverPublicKey(signature, hash);

    const originalPublicKey = identity.publicKey;

    expect(publicKey).to.be.equal(originalPublicKey);
  });

  it('should encrypt with the public key and decrypt with the private key', async () => {
    const identity = await IdentityHelper.generateIdentity();

    const message = 'info';
    const encryptedMessage = await IdentityHelper.encryptWithPublicKey(
      identity.compressedPublicKey,
      message
    );
    const originalMessage = await IdentityHelper.decryptWithPrivateKey(
      identity.privateKey,
      encryptedMessage
    );

    expect(message).to.be.equal(originalMessage);
  });

  it('should compute the same secret', async () => {
    const data = 'info';
    const identityFrom = await IdentityHelper.generateIdentity();
    const identityTo = await IdentityHelper.generateIdentity();

    const secret1 = IdentityHelper.computeSecret(
      identityFrom.privateKey,
      identityTo.publicKey
    );
    const secret2 = IdentityHelper.computeSecret(
      identityTo.privateKey,
      identityFrom.publicKey
    );

    const encrypted = IdentityHelper.encrypt(secret1, data);

    expect(secret1).to.be.equal(secret2);
    expect(data).to.be.equal(IdentityHelper.decrypt(secret2, encrypted));
  });

  it('should encrypt and decrypt a Buffer and an ArrayBuffer', async () => {
    function toArrayBuffer(buf) {
      var ab = new ArrayBuffer(buf.length);
      var view = new Uint8Array(ab);
      for (var i = 0; i < buf.length; ++i) {
        view[i] = buf[i];
      }

      return ab;
    }

    function arrayBuffersAreEqual(a, b) {
      return dataViewsAreEqual(new DataView(a), new DataView(b));
    }

    function dataViewsAreEqual(a, b) {
      if (a.byteLength !== b.byteLength) return false;
      for (let i = 0; i < a.byteLength; i++) {
        if (a.getUint8(i) !== b.getUint8(i)) return false;
      }
      return true;
    }

    const buffer = Buffer.from('hello');
    const arrayBuffer = toArrayBuffer(buffer);

    const identity = await IdentityHelper.generateIdentity();

    const encryptedBuffer = await IdentityHelper.encryptBuffer(
      identity,
      null,
      buffer
    );
    const encryptedArrayBuffer = await IdentityHelper.encryptArrayBuffer(
      identity,
      null,
      arrayBuffer
    );

    const decryptedBuffer = await IdentityHelper.decryptBuffer(
      identity,
      null,
      encryptedBuffer
    );
    const decryptedArrayBuffer = toArrayBuffer(
      await IdentityHelper.decryptBuffer(identity, null, encryptedArrayBuffer)
    );

    expect(Buffer.compare(buffer, decryptedBuffer)).to.be.equal(0);
    expect(arrayBuffersAreEqual(arrayBuffer, decryptedArrayBuffer)).to.be.true;
  });

  it('should generate a mnemonic with 12 words', async () => {
    const phrase = IdentityHelper.generateMnemonic();
    expect(phrase.split(' ').length).to.be.equal(12);
  });

  it('should generate a identity from a phrase', async () => {
    const seed = await IdentityHelper.generateSeed(
      'fetch shift common sting tree wild today eternal subject reflect follow inject'
    );
    const privateKey = IdentityHelper.derivePrivateKey(
      seed,
      // eslint-disable-next-line prettier/prettier
      'm/44\'/60\'/0\'/0/0'
    );
    const identity = await IdentityHelper.generateIdentity(privateKey);

    expect(identity.privateKey).to.be.equal(
      '431d7377ff7fdbd3e4076d284ea60343b8c3ce7e531bf8e18041ca5f64903dc6'
    );
    expect(identity.address).to.be.equal(
      '0xbd65f7961FdF889e1Bc62991383C3129C9e44dFb'
    );
  });
});
