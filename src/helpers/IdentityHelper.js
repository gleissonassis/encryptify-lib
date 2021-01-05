import EthCrypto from 'eth-crypto';
import Cryptr from 'cryptr';
import crypto from 'crypto';
import sha256 from 'js-sha256';

export default class IdentityHelper {
  generateHash(data) {
    return sha256(data);
  }

  sign (privateKey, hash) {
    return EthCrypto.sign(privateKey, hash);
  }

  async generateIdentity (privateKey) {
    if (privateKey) {
      const publicKey = EthCrypto.publicKeyByPrivateKey(privateKey);
      const address = EthCrypto.publicKey.toAddress(publicKey);
      const compressedPublicKey = this.compressPublicKey(publicKey);
      
      return {
        privateKey,
        publicKey,
        address,
        compressedPublicKey,
      };
    } else {
      const identity = EthCrypto.createIdentity();

      return {
        ...identity,
        compressedPublicKey: this.compressPublicKey(identity.publicKey),
      };
    }
  }

  encrypt (secret, content) {
    var cryptr = new Cryptr(secret);
    return cryptr.encrypt(content);
  }

  decrypt (secret, content) {
    var cryptr = new Cryptr(secret);
    return cryptr.decrypt(content);
  }

  compressPublicKey (publicKey) {
    return EthCrypto.publicKey.compress(publicKey);
  }

  isCompressedPublicKey(publicKey) {
    return publicKey && (publicKey.startsWith('02') || publicKey.startsWith('03'));
  }

  recoverAddress (signature, hash) {
    return  EthCrypto.recover(signature, hash);
  }

  recoverPublicKey (signature, hash) {
    return  EthCrypto.recoverPublicKey(signature, hash);
  }

  computeSecret (fromPrivateKey, toPublicKey) {
    const from = crypto.createECDH('secp256k1');
    const to = crypto.createECDH('secp256k1');

    from.setPrivateKey(Buffer.from(fromPrivateKey.substr(2), 'hex'));

    let decompressedPublicKey = EthCrypto.publicKey.decompress(toPublicKey);

    if (!decompressedPublicKey.startsWith('04')) {
      decompressedPublicKey = '04' + decompressedPublicKey;
    }

    return from.computeSecret(Buffer.from(decompressedPublicKey, 'hex')).toString('hex');
  }

  async encryptWithPublicKey (publicKey, message) {
    const encryptedData = await EthCrypto.encryptWithPublicKey(publicKey, message);
    const hexString = EthCrypto.cipher.stringify(encryptedData);

    return EthCrypto.hex.compress(hexString, true);
  }

  async decryptWithPrivateKey (privateKey, compressedEncryptedData) {
    const decompressedHexString = EthCrypto.hex.decompress(compressedEncryptedData, true);
    const encryptedData = EthCrypto.cipher.parse(decompressedHexString.substr(2));

    return await EthCrypto.decryptWithPrivateKey(privateKey, encryptedData);
  }
}