import chai from 'chai';
const { expect } = chai;
import IdentityHelper from '../../src/helpers/IdentityHelper.js';

describe('IdentityHelper', () => {
  const commonIdentity = { 
    address: '0x3f243FdacE01Cfd9719f7359c94BA11361f32471',
    privateKey: '0x107be946709e41b7895eea9f2dacf998a0a9124acbb786f0fd1a826101581a07',
    publicKey: 'bf1cc3154424dc22191941d9f4f50b063a2b663a2337e5548abea633c1d06eceacf2b81dd326d278cd992d5e03b0df140f2df389ac9a1c2415a220a4a9e8c046',
    compressedPublicKey: '02bf1cc3154424dc22191941d9f4f50b063a2b663a2337e5548abea633c1d06ece',
  };

  const identityHelper = new IdentityHelper();

  it('should generate a new identity', async () => {
    const identity = await identityHelper.generateIdentity();

    expect(identity).to.have.property('privateKey');
    expect(identity).to.have.property('publicKey');
    expect(identity).to.have.property('compressedPublicKey');
    expect(identity).to.have.property('address');
  });

  it('should generate an identity based on a private key', async () => {
    const originalIdentity = await identityHelper.generateIdentity();
    const identity = await identityHelper.generateIdentity(originalIdentity.privateKey);

    expect(identity.privateKey).to.equal(identity.privateKey);
    expect(identity.publicKey).to.equal(identity.publicKey);
    expect(identity.compressedPublicKey).to.equal(identity.compressedPublicKey);
    expect(identity.address).to.equal(identity.address);
  });

  it('should encrypt and decrypt data using a simetrict key', async () => {
    const data = 'info';
    const key = 'key';

    expect(data).to.be.equal(identityHelper.decrypt(key, identityHelper.encrypt(key, data)));
  });

  it('should generate a valid hash from text', () => {
    const data = 'info';

    const hash = identityHelper.generateHash(data);

    expect(hash).to.be.equal('06271baf49532c879aa3c58b48671884bcc858f09197412d682750496c33e1e1');
  });

  it('should compress a public key', () => {
    expect(identityHelper.compressPublicKey(commonIdentity.publicKey)).to.be.equal('02bf1cc3154424dc22191941d9f4f50b063a2b663a2337e5548abea633c1d06ece');
  });

  it('should return true to a compressed publicKey', () => {
    const compressedPublicKey = '02bf1cc3154424dc22191941d9f4f50b063a2b663a2337e5548abea633c1d06ece';
    expect(identityHelper.isCompressedPublicKey(compressedPublicKey)).to.be.true;
  });

  it('should return false to an uncompressed publicKey', () => {
    const uncompressedPublicKey = 'bf1cc3154424dc22191941d9f4f50b063a2b663a2337e5548abea633c1d06eceacf2b81dd326d278cd992d5e03b0df140f2df389ac9a1c2415a220a4a9e8c046';
    expect(identityHelper.isCompressedPublicKey(uncompressedPublicKey)).to.be.false;
  });

  it('should sign a hashed message with the private key', () => {
    const messageg = 'info';
    const hash = identityHelper.generateHash(messageg);
    const signature = identityHelper.sign(commonIdentity.privateKey, hash);

    expect(signature).to.be.equal('0xa3468121547bf3083fd7d500fb56c3787462b6a56893cca43219f7e78331351140950f752d7cf32374782043708e9cfd4dd4cf6d5fa5397d9f1523e6f2fef77f1c');
  });

  it('should recover the address from a signature and the original hash', async () => {
    const identity = await identityHelper.generateIdentity();

    const messageg = 'info';
    const hash = identityHelper.generateHash(messageg);
    const signature = identityHelper.sign(identity.privateKey, hash);
    const address = identityHelper.recoverAddress(signature, hash);

    const originalAddress = identity.address;

    expect(address).to.be.equal(originalAddress);
  });

  it('should recover the public key from a signature and the original hash', async () => {
    const identity = await identityHelper.generateIdentity();

    const messageg = 'info';
    const hash = identityHelper.generateHash(messageg);
    const signature = identityHelper.sign(identity.privateKey, hash);
    const publicKey = identityHelper.recoverPublicKey(signature, hash);

    const originalPublicKey = identity.publicKey;

    expect(publicKey).to.be.equal(originalPublicKey);
  });

  it('should encrypt with the public key and decrypt with the private key', async () => {
    const identity = await identityHelper.generateIdentity();

    const message = 'info';
    const encryptedMessage = await identityHelper.encryptWithPublicKey(identity.compressedPublicKey, message);
    const originalMessage = await identityHelper.decryptWithPrivateKey(identity.privateKey, encryptedMessage);

    expect(message).to.be.equal(originalMessage);
  });

  it.only('should compute the same secret', async () => {
    const data = 'info';
    const identityFrom = await identityHelper.generateIdentity();
    const identityTo = await identityHelper.generateIdentity();

    const secret1 = identityHelper.computeSecret(identityFrom.privateKey, identityTo.publicKey);
    const secret2 = identityHelper.computeSecret(identityTo.privateKey, identityFrom.publicKey);

    const encrypted = identityHelper.encrypt(secret1, data);

    expect(secret1).to.be.equal(secret2);
    expect(data).to.be.equal(identityHelper.decrypt(secret2, encrypted));
  });
});
