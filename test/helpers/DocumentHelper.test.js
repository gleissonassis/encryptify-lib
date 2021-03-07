const chai = require('chai');
const { expect } = chai;
const { DocumentHelper, IdentityHelper } = require('../../src/index');

describe('DocumentHelper', () => {
  const path = './test/helpers';
  const file = 'test.jpg';

  const encryptedFileName = `${path}/${file}.encryptify`;
  const originalFile = `${file.split('.')[0]}.original.${file.split('.')[1]}`;
  const filePath = `${path}/${file}`;
  const originalFilePath = `${path}/${originalFile}`;

  it('should open a file, encrypt with the public key decrypt with private key and compare the data', async () => {
    const identity = await IdentityHelper.generateIdentity();

    const encoding = DocumentHelper.isBinaryPath(filePath) ? 'binary' : 'utf8';

    const fileContent = await DocumentHelper.openFile(filePath, encoding);
    const encryptedFileContent = await IdentityHelper.encryptWithPublicKey(
      identity.compressedPublicKey,
      fileContent
    );

    await DocumentHelper.writeFile(
      encryptedFileName,
      encryptedFileContent,
      'utf8'
    );

    const encryptedFile = await DocumentHelper.openFile(
      encryptedFileName,
      'utf8'
    );
    const decryptedFile = await IdentityHelper.decryptWithPrivateKey(
      identity.privateKey,
      encryptedFile
    );

    await DocumentHelper.writeFile(originalFilePath, decryptedFile, encoding);

    const newFileContent = await DocumentHelper.openFile(
      originalFilePath,
      encoding
    );

    expect(fileContent).to.be.equal(newFileContent);
  });

  it('should create a string version of a encrypted file metadata', async () => {
    const identity = await IdentityHelper.generateIdentity();
    const targetIdentity = await IdentityHelper.generateIdentity();

    const result = await DocumentHelper.stringify(
      identity,
      targetIdentity.compressedPublicKey,
      {
        type: 'document',
        title: 'File title',
        mimeType: 'text/plain',
        path: '/',
        content: Buffer.from('hello'),
        metadata: {
          key: 'value',
        },
      }
    );

    const file = await DocumentHelper.parse(
      targetIdentity,
      identity.compressedPublicKey,
      result
    );

    expect('File title').to.be.equal(file.title);
    expect('/').to.be.equal(file.path);
    expect('document').to.be.equal(file.type);
    expect('text/plain').to.be.equal(file.mimeType);
    expect('hello').to.be.equal(file.content.toString());
    expect(file.metadata.key).to.be.equal('value');
  });

  it('should fail to decrypt with an invalid identity (content)', async () => {
    const identity = await IdentityHelper.generateIdentity();
    const wrongIdentity = await IdentityHelper.generateIdentity();

    const result = await DocumentHelper.stringify(identity, null, {
      title: 'File title',
      mimeType: 'text/plain',
      path: '/',
      content: Buffer.from('hello'),
    });

    try {
      await DocumentHelper.parse(wrongIdentity, null, result);
      throw {};
    } catch (e) {
      expect(e.code).to.be.equal('INVALID_SIGNATURE');
    }

    try {
      const file = await DocumentHelper.parse(
        wrongIdentity,
        wrongIdentity.compressedPublicKey,
        result
      );
      console.log(file);
      throw {};
    } catch (e) {
      expect(e.code).to.be.equal('INVALID_SIGNATURE');
    }
  });

  it('should fail to decrypt with an invalid identity (path)', async () => {
    const identity = await IdentityHelper.generateIdentity();
    const wrongIdentity = await IdentityHelper.generateIdentity();

    const result = await DocumentHelper.stringify(identity, null, {
      path: '/',
    });

    try {
      await DocumentHelper.parse(wrongIdentity, null, result);
      throw {};
    } catch (e) {
      expect(e.code).to.be.equal('INVALID_SIGNATURE');
    }
  });

  it('should fail to decrypt with an invalid identity (path)', async () => {
    const identity = await IdentityHelper.generateIdentity();
    const wrongIdentity = await IdentityHelper.generateIdentity();

    const result = await DocumentHelper.stringify(identity, null, {
      metadata: {
        key: 'value',
      },
    });

    try {
      await DocumentHelper.parse(wrongIdentity, null, result);
      throw {};
    } catch (e) {
      expect(e.code).to.be.equal('INVALID_SIGNATURE');
    }
  });

  it('should create a string version of a encrypted file with metadata content only', async () => {
    const identity = await IdentityHelper.generateIdentity();
    const targetIdentity = await IdentityHelper.generateIdentity();

    const result = await DocumentHelper.stringify(
      identity,
      targetIdentity.compressedPublicKey,
      {
        title: 'File title',
        mimeType: 'text/plain',
        path: '/',
        metadata: {
          key: 'value',
        },
        indexes: [
          {
            key: 'email',
            value: 'email@domain',
          },
          {
            key: 'category',
            value: 'financial',
          },
        ],
        keywords: [
          {
            value: 'file',
          },
          {
            value: 'document',
          },
        ],
      }
    );

    const file = await DocumentHelper.parse(
      targetIdentity,
      identity.compressedPublicKey,
      result
    );

    expect('File title').to.be.equal(file.title);
    expect('/').to.be.equal(file.path);
    expect('text/plain').to.be.equal(file.mimeType);

    expect('email').to.be.equal(file.indexes[0].key);
    expect('email@domain').to.be.equal(file.indexes[0].value);
    expect('value').to.be.equal(file.metadata.key);
    expect('file').to.be.equal(file.keywords[0].value);
    expect('document').to.be.equal(file.keywords[1].value);
    expect(
      '82244417f956ac7c599f191593f7e441a4fafa20a4158fd52e154f1dc4c8ed92'
    ).to.be.equal(file.indexes[0].keyHash);
    expect(
      'a0f42a1eae5f387a50966ac4b183270eae6832d2823ca5ea9f4685fa248fdf7d'
    ).to.be.equal(file.indexes[0].valueHash);

    expect('category').to.be.equal(file.indexes[1].key);
    expect('financial').to.be.equal(file.indexes[1].value);
    expect(
      'edb2cd3b74c999af70f0b7054990f2072dc6e10a847af6ed05954b8994b730fe'
    ).to.be.equal(file.indexes[1].keyHash);
    expect(
      'fed0e4820af42571c936e28300ccb88026f72e075232358cd1fae4e802fe902b'
    ).to.be.equal(file.indexes[1].valueHash);
  });
});
