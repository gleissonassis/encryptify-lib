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
        title: 'File title',
        mimeType: 'text/plain',
        path: '/',
        content: Buffer.from('hello'),
        keywords: ['hello', 'world'],
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
    expect('text/plain').to.be.equal(file.mimeType);
    expect('hello').to.be.equal(file.content.toString());
    expect(file.keywords.length).to.be.equal(2);
    expect(file.keywords[0]).to.be.equal(
      '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    );
    expect(file.keywords[1]).to.be.equal(
      '486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7'
    );
    expect(file.metadata.key).to.be.equal('value');
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
        indexes: {
          email: 'email@domain',
          category: 'financial',
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
    expect('text/plain').to.be.equal(file.mimeType);
    expect(Object.keys(file.indexes).length).to.be.equal(2);
    expect(
      file.indexes[
        '82244417f956ac7c599f191593f7e441a4fafa20a4158fd52e154f1dc4c8ed92'
      ]
    ).to.be.equal(
      'a0f42a1eae5f387a50966ac4b183270eae6832d2823ca5ea9f4685fa248fdf7d'
    );
    expect(
      file.indexes[
        'edb2cd3b74c999af70f0b7054990f2072dc6e10a847af6ed05954b8994b730fe'
      ]
    ).to.be.equal(
      'fed0e4820af42571c936e28300ccb88026f72e075232358cd1fae4e802fe902b'
    );
    expect(file.metadata.key).to.be.equal('value');
  });

  it('should fail to stringify a content without the content and metadata attribute', async () => {
    try {
      const identity = await IdentityHelper.generateIdentity();
      const targetIdentity = await IdentityHelper.generateIdentity();

      await DocumentHelper.stringify(
        identity,
        targetIdentity.compressedPublicKey,
        {
          title: 'File title',
          mimeType: 'text/plain',
          path: '/',
        }
      );
      throw {};
    } catch (e) {
      expect(e.code).to.be.equal('REQUIRED_FIELDS');
    }
  });

  it('should fail to stringify a content without title, mimeType and path', async () => {
    try {
      const identity = await IdentityHelper.generateIdentity();
      const targetIdentity = await IdentityHelper.generateIdentity();

      await DocumentHelper.stringify(
        identity,
        targetIdentity.compressedPublicKey,
        {}
      );
      throw {};
    } catch (e) {
      expect(e.code).to.be.equal('REQUIRED_FIELDS');
    }
  });
});
