import chai from 'chai';
const { expect } = chai;
import { FileHelper, IdentityHelper } from '../../src/index.js';

describe('FileHelper', () => {
  const path = './test/helpers';
  const file = 'test.jpg';

  const encryptedFileName = `${path}/${file}.encryptify`;
  const originalFile = `${file.split('.')[0]}.original.${file.split('.')[1]}`;
  const filePath = `${path}/${file}`;
  const originalFilePath = `${path}/${originalFile}`;

  it('should open a file, encrypt with the public key decrypt with private key and compare the data', async () => {
    const identity = await IdentityHelper.generateIdentity();

    const encoding = FileHelper.isBinaryPath(filePath) ? 'binary':'utf8';

    const fileContent = await FileHelper.openFile(filePath, encoding);
    const encryptedFileContent = await IdentityHelper.encryptWithPublicKey(identity.compressedPublicKey, fileContent);

    await FileHelper.writeFile(encryptedFileName, encryptedFileContent, 'utf8');

    const encryptedFile = await FileHelper.openFile(encryptedFileName, 'utf8');
    const decryptedFile = await IdentityHelper.decryptWithPrivateKey(identity.privateKey, encryptedFile);

    await FileHelper.writeFile(originalFilePath, decryptedFile, encoding);

    const newFileContent = await FileHelper.openFile(originalFilePath, encoding);

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
  });
});
