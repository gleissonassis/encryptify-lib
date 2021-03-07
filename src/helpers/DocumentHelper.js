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

  static async _encryptIndexes(identity, targetAccount, indexes) {
    const newIndexes = [];

    for (const index of indexes) {
      newIndexes.push({
        key: await IdentityHelper.encryptBuffer(
          identity,
          targetAccount,
          Buffer.from(this._getValue(index.key))
        ),
        value: await IdentityHelper.encryptBuffer(
          identity,
          targetAccount,
          Buffer.from(this._getValue(index.value))
        ),
        keyHash: IdentityHelper.generateHash(index.key),
        valueHash: IdentityHelper.generateHash(index.value),
      });
    }

    return newIndexes;
  }

  static async _encryptKeywords(identity, targetAccount, keywords) {
    const newKeywords = [];

    for (const keyword of keywords) {
      newKeywords.push({
        value: await IdentityHelper.encryptBuffer(
          identity,
          targetAccount,
          Buffer.from(this._getValue(keyword.value))
        ),
        valueHash: IdentityHelper.generateHash(keyword.value),
      });
    }

    return newKeywords;
  }

  static _getValue(value) {
    if (value === Object(value) || Array.isArray(value)) {
      return JSON.stringify(value);
    } else {
      return value.toString();
    }
  }

  static _hashAndSign(
    identity,
    targetAccount,
    document,
    attr,
    encryptedDocument
  ) {
    const hashKey = `${attr}Hash`;
    const signatureKey = `${hashKey}Signature`;

    encryptedDocument[hashKey] = IdentityHelper.generateHash(
      this._getValue(document[attr])
    );

    encryptedDocument[signatureKey] = IdentityHelper.sign(
      identity.privateKey,
      encryptedDocument[hashKey]
    );
  }
  static async stringify(identity, targetAccount, document) {
    const ignoredAttributes = [
      'indexes',
      'keywords',
      'type',
      'objectId',
      'originalFileSize',
    ];
    const hashableAttributes = ['metadata', 'content', 'path'];

    const encryptedDocument = {};

    for (const attr in document) {
      if (ignoredAttributes.includes(attr) || document[attr] === null) {
        encryptedDocument[attr] = document[attr];
        continue;
      }

      if (attr === 'content') {
        encryptedDocument[attr] = await IdentityHelper.encryptBuffer(
          identity,
          targetAccount,
          document[attr]
        );
      } else {
        encryptedDocument[attr] = await IdentityHelper.encryptBuffer(
          identity,
          targetAccount,
          Buffer.from(this._getValue(document[attr]))
        );
      }

      if (hashableAttributes.includes(attr)) {
        await this._hashAndSign(
          identity,
          targetAccount,
          document,
          attr,
          encryptedDocument
        );
      }
    }

    if (document.keywords) {
      encryptedDocument.keywords = await this._encryptKeywords(
        identity,
        targetAccount,
        document.keywords
      );
    }

    if (document.indexes) {
      encryptedDocument.indexes = await DocumentHelper._encryptIndexes(
        identity,
        targetAccount,
        document.indexes
      );
    }

    encryptedDocument.objectId = document.objectId;
    encryptedDocument.type = document.type;
    encryptedDocument.format = 'v1';

    return JSON.stringify(encryptedDocument);
  }

  static _isJSON(str) {
    if (/^\s*$/.test(str)) return false;
    str = str.replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g, '@');
    str = str.replace(
      /"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g,
      ']'
    );
    str = str.replace(/(?:^|:|,)(?:\s*\[)+/g, '');
    return /^[\],:{}\s]*$/.test(str);
  }

  static async parse(identity, targetAccount, fileContent) {
    const ignoredAttributes = [
      'objectId',
      'metadataHash',
      'originalFileSize',
      'metadataHashSignature',
      'contentHash',
      'contentHashSignature',
      'pathHash',
      'pathHashSignature',
      'format',
      'indexes',
      'keywords',
      'type',
      'id',
      'network',
      'from',
      'createdAt',
      'updatedAt',
    ];
    const encryptedDocument = JSON.parse(fileContent);
    const decryptedDocument = {};

    const signature =
      encryptedDocument.contentHashSignature ||
      encryptedDocument.metadataHashSignature ||
      encryptedDocument.pathHashSignature;
    const hash =
      encryptedDocument.contentHash ||
      encryptedDocument.metadataHash ||
      encryptedDocument.pathHash;

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

    for (const attr in encryptedDocument) {
      if (
        ignoredAttributes.includes(attr) ||
        encryptedDocument[attr] === null
      ) {
        decryptedDocument[attr] = encryptedDocument[attr];
        continue;
      }

      try {
        decryptedDocument[attr] = await IdentityHelper.decryptBuffer(
          identity,
          targetAccount,
          encryptedDocument[attr]
        );
      } catch (e) {
        decryptedDocument[attr] = encryptedDocument[attr];
      }

      if (attr !== 'content') {
        decryptedDocument[attr] = decryptedDocument[attr].toString();

        if (
          decryptedDocument[attr] &&
          DocumentHelper._isJSON(decryptedDocument[attr])
        ) {
          decryptedDocument[attr] = JSON.parse(decryptedDocument[attr]);
        }
      }
    }

    if (encryptedDocument.keywords) {
      for (const keyword of encryptedDocument.keywords) {
        keyword.value = (
          await IdentityHelper.decryptBuffer(
            identity,
            targetAccount,
            keyword.value
          )
        ).toString();
      }
    }

    if (encryptedDocument.indexes) {
      for (const index of encryptedDocument.indexes) {
        index.key = (
          await IdentityHelper.decryptBuffer(identity, targetAccount, index.key)
        ).toString();

        index.value = (
          await IdentityHelper.decryptBuffer(
            identity,
            targetAccount,
            index.value
          )
        ).toString();
      }
    }

    return decryptedDocument;
  }
};
