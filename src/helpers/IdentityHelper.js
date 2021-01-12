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

  encryptToTargetPublicKey(privateKey, targetPublicKey, content) {
    const secret = ih.computeSecret(privateKey, targetPublicKey);
    return this.encrypt(secret, content);
  }

  decryptFromTargetPublicKey(privateKey, targetPublicKey, content) {
    const secret = ih.computeSecret(privateKey, targetPublicKey);
    return this.decrypt(secret, content);
  }

  async encryptBuffer ({publicKey, compressedPublicKey, privateKey}, targetPublicKey, buffer) {
    if (!targetPublicKey) {
      return await this.encryptWithPublicKey(
        publicKey || compressedPublicKey, 
        buffer.toString('hex')
      );
    } else {
      return ih.encryptToTargetPublicKey(privateKey, targetPublicKey, buffer.toString('hex'));
    }
  }

  async decryptBuffer ({privateKey}, targetPublicKey, encryptedBuffer) {
    let decryptedBuffer = null;

    if (!targetPublicKey) {
      decryptedBuffer = await this.decryptWithPrivateKey(
        privateKey,
        encryptedBuffer
      );
    } else {
      decryptedBuffer = this.decryptFromTargetPublicKey(
        privateKey,
        targetPublicKey,
        encryptedBuffer
      );
    }

    return Buffer.from(decryptedBuffer, 'hex');
  }

  encryptArrayBuffer (identity, targetPublicKey, arrayBuffer) {
    return this.encryptBuffer(
      identity, 
      targetPublicKey, 
      this.toBuffer(arrayBuffer)
    );
  }

  toBuffer (ab) {
    var buf = Buffer.alloc(ab.byteLength);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buf.length; ++i) {
      buf[i] = view[i];
    }

    return buf;
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