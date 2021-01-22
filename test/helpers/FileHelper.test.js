const chai = require('chai');
const { expect } = chai;
const { FileHelper, IdentityHelper } = require('../../src/index');

describe('FileHelper', () => {
  const path = './test/helpers';
  const file = 'test.jpg';

  const encryptedFileName = `${path}/${file}.encryptify`;
  const originalFile = `${file.split('.')[0]}.original.${file.split('.')[1]}`;
  const filePath = `${path}/${file}`;
  const originalFilePath = `${path}/${originalFile}`;

  it('should open a file, encrypt with the public key decrypt with private key and compare the data', async () => {
    const identity = await IdentityHelper.generateIdentity();

    const encoding = FileHelper.isBinaryPath(filePath) ? 'binary' : 'utf8';

    const fileContent = await FileHelper.openFile(filePath, encoding);
    const encryptedFileContent = await IdentityHelper.encryptWithPublicKey(
      identity.compressedPublicKey,
      fileContent
    );

    await FileHelper.writeFile(encryptedFileName, encryptedFileContent, 'utf8');

    const encryptedFile = await FileHelper.openFile(encryptedFileName, 'utf8');
    const decryptedFile = await IdentityHelper.decryptWithPrivateKey(
      identity.privateKey,
      encryptedFile
    );

    await FileHelper.writeFile(originalFilePath, decryptedFile, encoding);

    const newFileContent = await FileHelper.openFile(
      originalFilePath,
      encoding
    );

    expect(fileContent).to.be.equal(newFileContent);
  });

  it('should create a string version of a encrypted file metadata', async () => {
    const identity = await IdentityHelper.generateIdentity();
    const targetIdentity = await IdentityHelper.generateIdentity();

    const result = await FileHelper.stringify(
      identity,
      targetIdentity.compressedPublicKey,
      {
        title: 'File title',
        mimeType: 'text/plain',
        path: '/',
        content: Buffer.from('hello'),
        indexes: [
          '97817c0c49994eb500ad0a5e7e2d8aed51977b26424d508f66e4e8887746a152',
          '2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683',
        ],
        metadata: {
          key: 'value',
        },
      }
    );

    const file = await FileHelper.parse(
      targetIdentity,
      identity.compressedPublicKey,
      result
    );

    expect('File title').to.be.equal(file.title);
    expect('/').to.be.equal(file.path);
    expect('text/plain').to.be.equal(file.mimeType);
    expect('hello').to.be.equal(file.content.toString());
    expect(file.indexes.length).to.be.equal(2);
    expect(file.metadata.key).to.be.equal('value');
  });

  it('should create a string version of a encrypted file with metadata content only', async () => {
    const identity = await IdentityHelper.generateIdentity();
    const targetIdentity = await IdentityHelper.generateIdentity();

    const result = await FileHelper.stringify(
      identity,
      targetIdentity.compressedPublicKey,
      {
        title: 'File title',
        mimeType: 'text/plain',
        path: '/',
        indexes: [
          '97817c0c49994eb500ad0a5e7e2d8aed51977b26424d508f66e4e8887746a152',
          '2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683',
        ],
        metadata: {
          key: 'value',
        },
      }
    );

    const file = await FileHelper.parse(
      targetIdentity,
      identity.compressedPublicKey,
      result
    );

    expect('File title').to.be.equal(file.title);
    expect('/').to.be.equal(file.path);
    expect('text/plain').to.be.equal(file.mimeType);
    expect(file.indexes.length).to.be.equal(2);
    expect(file.metadata.key).to.be.equal('value');
  });

  it('should fail to stringify a content without the content and metadata attribute', async () => {
    try {
      const identity = await IdentityHelper.generateIdentity();
      const targetIdentity = await IdentityHelper.generateIdentity();

      await FileHelper.stringify(identity, targetIdentity.compressedPublicKey, {
        title: 'File title',
        mimeType: 'text/plain',
        path: '/',
        indexes: [
          '97817c0c49994eb500ad0a5e7e2d8aed51977b26424d508f66e4e8887746a152',
          '2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683',
        ],
      });
      throw {};
    } catch (e) {
      expect(e.code).to.be.equal('REQUIRED_FIELDS');
    }
  });

  it('should fail to stringify a content without title, mimeType and path', async () => {
    try {
      const identity = await IdentityHelper.generateIdentity();
      const targetIdentity = await IdentityHelper.generateIdentity();

      await FileHelper.stringify(identity, targetIdentity.compressedPublicKey, {
        indexes: [
          '97817c0c49994eb500ad0a5e7e2d8aed51977b26424d508f66e4e8887746a152',
          '2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683',
        ],
      });
      throw {};
    } catch (e) {
      expect(e.code).to.be.equal('REQUIRED_FIELDS');
    }
  });

  it('should fail to stringify a content with invalid indexes', async () => {
    try {
      const identity = await IdentityHelper.generateIdentity();
      const targetIdentity = await IdentityHelper.generateIdentity();

      await FileHelper.stringify(identity, targetIdentity.compressedPublicKey, {
        title: 'File title',
        mimeType: 'text/plain',
        path: '/',
        content: Buffer.from('hello'),
        indexes: [
          'teste',
          '2c70e12b7a0646f92279f427c7b38e7334d8e5389cff167a1dc30e73f826b683',
        ],
        metadata: {
          key: 'value',
        },
      });

      throw {};
    } catch (e) {
      expect(e.code).to.be.equal('INVALID_INDEX');
      expect(e.invalidIndex).to.be.equal('teste');
    }
  });
});
