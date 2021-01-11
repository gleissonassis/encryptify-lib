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

  const fileHelper = new FileHelper();

  it('should open a file, encrypt with the public key decrypt with private key and compare the data', async () => {
    const ih = new IdentityHelper();
    const identity = await ih.generateIdentity();

    const encoding = fileHelper.isBinaryPath(filePath) ? 'binary':'utf8';

    const fileContent = await fileHelper.openFile(filePath, encoding);
    const encryptedFileContent = await ih.encryptWithPublicKey(identity.compressedPublicKey, fileContent);

    await fileHelper.writeFile(encryptedFileName, encryptedFileContent, 'utf8');

    const encryptedFile = await fileHelper.openFile(encryptedFileName, 'utf8');
    const decryptedFile = await ih.decryptWithPrivateKey(identity.privateKey, encryptedFile);

    await fileHelper.writeFile(originalFilePath, decryptedFile, encoding);

    const newFileContent = await fileHelper.openFile(originalFilePath, encoding);

    expect(fileContent).to.be.equal(newFileContent);
  });
});
