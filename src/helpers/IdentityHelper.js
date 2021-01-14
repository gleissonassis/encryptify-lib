import EthCrypto from 'eth-crypto';
import Cryptr from 'cryptr';
import crypto from 'crypto';
import sha256 from 'js-sha256';

export default class IdentityHelper {
  static generateHash(data) {
    return sha256(data);
  }

  static sign (privateKey, hash) {
    return EthCrypto.sign(privateKey, hash);
  }

  static async generateIdentity (privateKey) {
    if (privateKey) {
      const publicKey = EthCrypto.publicKeyByPrivateKey(privateKey);
      const address = EthCrypto.publicKey.toAddress(publicKey);
      const compressedPublicKey = IdentityHelper.compressPublicKey(publicKey);
      
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
        compressedPublicKey: IdentityHelper.compressPublicKey(identity.publicKey),
      };
    }
  }

  static encrypt (secret, content) {
    var cryptr = new Cryptr(secret);
    return cryptr.encrypt(content);
  }

  static decrypt (secret, content) {
    var cryptr = new Cryptr(secret);
    return cryptr.decrypt(content);
  }

  static compressPublicKey (publicKey) {
    return EthCrypto.publicKey.compress(publicKey);
  }

  static isCompressedPublicKey(publicKey) {
    return publicKey && (publicKey.startsWith('02') || publicKey.startsWith('03'));
  }

  static recoverAddress (signature, hash) {
    return  EthCrypto.recover(signature, hash);
  }

  static recoverPublicKey (signature, hash) {
    return  EthCrypto.recoverPublicKey(signature, hash);
  }

  static computeSecret (fromPrivateKey, toPublicKey) {
    const from = crypto.createECDH('secp256k1');
    const to = crypto.createECDH('secp256k1');

    from.setPrivateKey(Buffer.from(fromPrivateKey.substr(2), 'hex'));

    let decompressedPublicKey = EthCrypto.publicKey.decompress(toPublicKey);

    if (!decompressedPublicKey.startsWith('04')) {
      decompressedPublicKey = '04' + decompressedPublicKey;
    }

    return from.computeSecret(Buffer.from(decompressedPublicKey, 'hex')).toString('hex');
  }

  static encryptToTargetPublicKey(privateKey, targetPublicKey, content) {
    const secret = IdentityHelper.computeSecret(privateKey, targetPublicKey);
    return IdentityHelper.encrypt(secret, content);
  }

  static decryptFromTargetPublicKey(privateKey, targetPublicKey, content) {
    const secret = IdentityHelper.computeSecret(privateKey, targetPublicKey);
    return IdentityHelper.decrypt(secret, content);
  }

  static async encryptBuffer ({publicKey, compressedPublicKey, privateKey}, targetPublicKey, buffer) {
    if (!targetPublicKey) {
      return await IdentityHelper.encryptWithPublicKey(
        publicKey || compressedPublicKey, 
        buffer.toString('hex')
      );
    } else {
      return IdentityHelper.encryptToTargetPublicKey(privateKey, targetPublicKey, buffer.toString('hex'));
    }
  }

  static async decryptBuffer ({privateKey}, targetPublicKey, encryptedBuffer) {
    let decryptedBuffer = null;

    if (!targetPublicKey) {
      decryptedBuffer = await IdentityHelper.decryptWithPrivateKey(
        privateKey,
        encryptedBuffer
      );
    } else {
      decryptedBuffer = IdentityHelper.decryptFromTargetPublicKey(
        privateKey,
        targetPublicKey,
        encryptedBuffer
      );
    }

    return Buffer.from(decryptedBuffer, 'hex');
  }

  static encryptArrayBuffer (identity, targetPublicKey, arrayBuffer) {
    return IdentityHelper.encryptBuffer(
      identity, 
      targetPublicKey, 
      IdentityHelper.toBuffer(arrayBuffer)
    );
  }

  static toBuffer (ab) {
    var buf = Buffer.alloc(ab.byteLength);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buf.length; ++i) {
      buf[i] = view[i];
    }

    return buf;
  }

  static async encryptWithPublicKey (publicKey, message) {
    const encryptedData = await EthCrypto.encryptWithPublicKey(publicKey, message);
    const hexString = EthCrypto.cipher.stringify(encryptedData);

    return EthCrypto.hex.compress(hexString, true);
  }

  static async decryptWithPrivateKey (privateKey, compressedEncryptedData) {
    const decompressedHexString = EthCrypto.hex.decompress(compressedEncryptedData, true);
    const encryptedData = EthCrypto.cipher.parse(decompressedHexString.substr(2));

    return await EthCrypto.decryptWithPrivateKey(privateKey, encryptedData);
  }
}