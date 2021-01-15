import fs from 'fs';
import { getEncoding } from 'istextorbinary';
import isBinaryPath from 'is-binary-path';
import IdentityHelper from './IdentityHelper.js';

export default class FileHelper {
  static openFile (path, encoding) {
    return new Promise((resolve, reject) => {
      fs.readFile(path, encoding, (err,data) => {
        if (err) {
          reject(err);
        }
        resolve(data);
      });
    });
  }

  static writeFile (path, content, encoding) {
    return new Promise((resolve, reject) => {
      fs.writeFile(path, content, {encoding}, function (err) {
        if (err) return reject(err);
        resolve();
      });
    });
  }

  static async encryptFileContent (identity, targetPublicKey, filePath) {
    return IdentityHelper.encryptBuffer(
      identity, 
      targetPublicKey, 
      await this.openFile(filePath)
    );
  }

  static detectEncoding (buffer) {
    return getEncoding(buffer);
  }

  static isBinaryPath (path) {
    return isBinaryPath(path);
  }

  static async stringify (identity, targetAccount, {title, path, mimeType, content}) {
    const contentHash = IdentityHelper.generateHash(content);
    const contentHashSignature = IdentityHelper.sign(identity.privateKey, contentHash);

    const file = {
      title: await IdentityHelper.encryptBuffer(
        identity,
        targetAccount,
        Buffer.from(title)
      ),
      path: await IdentityHelper.encryptBuffer(
        identity,
        targetAccount,
        Buffer.from(path)
      ),
      mimeType: await IdentityHelper.encryptBuffer(
        identity,
        targetAccount,
        Buffer.from(mimeType)
      ),
      content: await IdentityHelper.encryptBuffer(
        identity,
        targetAccount,
        content
      ),
      mimeTypeHash: IdentityHelper.generateHash(mimeType),
      pathHash: IdentityHelper.generateHash(path),
      contentHash,
      contentHashSignature,
      format: 'v1',
    };

    return JSON.stringify(file);
  }

  static async parse (identity, targetAccount, fileContent) {
    const file = JSON.parse(fileContent);
    const recoveredAddress = IdentityHelper.recoverAddress(file.contentHashSignature, file.contentHash);

    if (!targetAccount && recoveredAddress !== identity.address) {
      throw {
        code: 'INVALID_SIGNATURE',
        exptedAddress: identity.address,
        recoveredAddress
      };
    } else if (recoveredAddress !== IdentityHelper.publickeyToETHAddress(targetAccount)) {
      throw {
        code: 'INVALID_SIGNATURE',
        exptedAddress: IdentityHelper.publickeyToETHAddress(targetAccount),
        recoveredAddress
      };
    }

    const [
      title, 
      mimeType, 
      path, 
      content
    ] = await Promise.all([
      IdentityHelper.decryptBuffer(identity, targetAccount, file.title),
      IdentityHelper.decryptBuffer(identity, targetAccount, file.mimeType),
      IdentityHelper.decryptBuffer(identity, targetAccount, file.path),
      file.content ? IdentityHelper.decryptBuffer(identity, targetAccount, file.content) : null,
    ]);

    return {
      title: title.toString(),
      mimeType: mimeType.toString(),
      path: path.toString(),
      content,
    };
  }
}