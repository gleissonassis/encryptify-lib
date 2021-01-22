const fs = require('fs');
const { getEncoding } = require('istextorbinary');
const isBinaryPath = require('is-binary-path');
const IdentityHelper = require('./IdentityHelper');

module.exports = class DocumentHelper {
  static openFile(path, encoding) {
    return new Promise((resolve, reject) => {
      fs.readFile(path, encoding, (err, data) => {
        if (err) {
          reject(err);
        }
        resolve(data);
      });
    });
  }

  static writeFile(path, content, encoding) {
    return new Promise((resolve, reject) => {
      fs.writeFile(path, content, { encoding }, function (err) {
        if (err) return reject(err);
        resolve();
      });
    });
  }

  static async encryptFileContent(identity, targetPublicKey, filePath) {
    return IdentityHelper.encryptBuffer(
      identity,
      targetPublicKey,
      await this.openFile(filePath)
    );
  }

  static detectEncoding(buffer) {
    return getEncoding(buffer);
  }

  static isBinaryPath(path) {
    return isBinaryPath(path);
  }

  static async stringify(
    identity,
    targetAccount,
    { title, path, mimeType, content, indexes, metadata, keywords }
  ) {
    if (!title || !path || !mimeType) {
      throw {
        status: 409,
        code: 'REQUIRED_FIELDS',
        message: 'Title, path, and mimeType are required fields',
      };
    }

    if (!content && !metadata) {
      throw {
        status: 409,
        code: 'REQUIRED_FIELDS',
        message: 'You must enter the content or metadata field',
      };
    }

    if (this.indexes && !Array.isArray(this.indexes)) {
      throw {
        status: 409,
        code: 'INDEXES_MUST_BE_ARRAY',
      };
    }

    let metadataHash = null;
    let metadataHashSignature = null;

    if (indexes) {
      const newIndexes = {};

      for (const index in indexes) {
        newIndexes[
          IdentityHelper.generateHash(index)
        ] = IdentityHelper.generateHash(indexes[index]);
      }

      indexes = newIndexes;
    }

    if (keywords && Array.isArray(keywords)) {
      keywords = keywords.map((keyword) =>
        IdentityHelper.generateHash(keyword)
      );
    }

    const contentHash = content ? IdentityHelper.generateHash(content) : null;
    const contentHashSignature = content
      ? IdentityHelper.sign(identity.privateKey, contentHash)
      : null;

    if (metadata) {
      const json = JSON.stringify(metadata);

      metadata = await IdentityHelper.encryptBuffer(
        identity,
        targetAccount,
        Buffer.from(json)
      );
      metadataHash = IdentityHelper.generateHash(json);
      metadataHashSignature = IdentityHelper.sign(
        identity.privateKey,
        metadataHash
      );
    }

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
      content: content
        ? await IdentityHelper.encryptBuffer(identity, targetAccount, content)
        : null,
      mimeTypeHash: IdentityHelper.generateHash(mimeType),
      pathHash: IdentityHelper.generateHash(path),
      contentHash,
      contentHashSignature,
      indexes,
      keywords,
      metadata,
      metadataHash,
      metadataHashSignature,
      format: 'v1',
    };

    return JSON.stringify(file);
  }

  static async parse(identity, targetAccount, fileContent) {
    const file = JSON.parse(fileContent);

    const signature = file.contentHashSignature || file.metadataHashSignature;
    const hash = file.contentHash || file.metadataHash;

    let recoveredAddress = IdentityHelper.recoverAddress(
      signature,
      hash
    ).toUpperCase();

    if (!targetAccount && recoveredAddress !== identity.address.toUpperCase()) {
      throw {
        code: 'INVALID_SIGNATURE',
        exptedAddress: identity.address,
        recoveredAddress,
      };
    } else if (
      targetAccount &&
      recoveredAddress !==
        IdentityHelper.publickeyToETHAddress(targetAccount).toUpperCase()
    ) {
      throw {
        code: 'INVALID_SIGNATURE',
        exptedAddress: IdentityHelper.publickeyToETHAddress(targetAccount),
        recoveredAddress,
      };
    }

    const [title, mimeType, path, content, metadata] = await Promise.all([
      IdentityHelper.decryptBuffer(identity, targetAccount, file.title),
      IdentityHelper.decryptBuffer(identity, targetAccount, file.mimeType),
      IdentityHelper.decryptBuffer(identity, targetAccount, file.path),
      file.content
        ? IdentityHelper.decryptBuffer(identity, targetAccount, file.content)
        : null,
      file.metadata
        ? IdentityHelper.decryptBuffer(identity, targetAccount, file.metadata)
        : null,
    ]);

    return {
      ...file,
      title: title.toString(),
      mimeType: mimeType.toString(),
      path: path.toString(),
      content,
      metadata: metadata ? JSON.parse(metadata.toString()) : null,
    };
  }
};
