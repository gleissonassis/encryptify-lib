import IdentityHelper from './helpers/IdentityHelper.js';
import FileHelper from './helpers/FileHelper.js';


export default class Program {
  constructor () {
    this.aliases = {};

    this.aliases['generate'] = this.generateIdentity.bind(this);
    this.aliases['check'] = this.checkIdentity.bind(this);
    this.aliases['show'] = this.showIdentity.bind(this);
    this.aliases['encrypt'] = this.encryptFile.bind(this);
    this.aliases['decrypt'] = this.decryptFile.bind(this);
    this.aliases['secret'] = this.showSecret.bind(this);
  }

  run (params) {
    return this.aliases[params.a](params);
  }

  async generateIdentity ({f, p, pk}) {
    const ih = new IdentityHelper();
    const fh = new FileHelper();

    console.log('Generating new identity...');
    const identity = await ih.generateIdentity(pk);
    const json = JSON.stringify(identity);

    console.log('Encrypting the identity...');
    const encryptedJSON = ih.encrypt(p.toString(), json);

    console.log(`Saving identity to ${f} ...`);
    await fh.writeFile(f, encryptedJSON, 'utf8');

    console.log(`Identity stored successfully in ${f}!`);
  }

  async openIdentity ({f, p}) {
    const ih = new IdentityHelper();
    const fh = new FileHelper();

    const encryptedJSON = await fh.openFile(f, 'utf8');
    return JSON.parse(ih.decrypt(p.toString(), encryptedJSON));
  }

  async checkIdentity ({f, p}) {
    console.log(`Checking identity file...`);
    
    const identity = await this.openIdentity({f, p});

    console.log(`Identity file opened successfully! \n\nPublic key: \n${identity.publicKey}`);
  }

  async showIdentity ({f, p}) {
    const identity = await this.openIdentity({f, p});

    console.log(`Identity file opened successfully!`);
    console.log(identity);
  }

  async encryptFile ({f, p, s, e, o, t}) {
    const ih = new IdentityHelper();
    const fh = new FileHelper();

    console.log('Opening identity file...');
    const identity = await this.openIdentity({f, p});
    console.log(`Identity file opened successfully!\n\nPublic key:\n${identity.publicKey}`);

    const encoding = e || fh.isBinaryPath(s) ? 'binary' : 'utf8';

    console.log(`Opening source file ${s} as ${encoding}...`);

    const fileContent = await fh.openFile(s, encoding);

    console.log(`Encrypting file content...`);

    let encryptedFileContent = null;

    if (!t) {
      encryptedFileContent = await ih.encryptWithPublicKey(identity.compressedPublicKey, fileContent);
    } else {
      console.log(`Encrypting using compted secret to ${t}`, )
      const secret = ih.computeSecret(identity.privateKey, t);
      encryptedFileContent = ih.encrypt(secret, fileContent);
    }

    const encryptedFileName = o || `${s}.encryptify`;
    console.log(`Saving encrypted file content to ${encryptedFileName}`);
    await fh.writeFile(encryptedFileName, encryptedFileContent, 'utf8');
  }

  async decryptFile ({f, p, s, e, o, t}) {
    const ih = new IdentityHelper();
    const fh = new FileHelper();

    console.log('Opening identity file...');
    const identity = await this.openIdentity({f, p});
    console.log(`Identity file opened successfully!\n\nPublic key:\n${identity.publicKey}`);

    console.log(`Opening encrypted file ${s} ...`);

    const encryptedFile = await fh.openFile(s, 'utf8');

    let decryptedFileContent = null;

    if (!t) {
      decryptedFileContent = await ih.decryptWithPrivateKey(identity.privateKey, encryptedFile);
    } else {
      console.log(`Decrypting using compted secret to ${t}`, )
      const secret = ih.computeSecret(identity.privateKey, t);
      decryptedFileContent = ih.decrypt(secret, encryptedFile);
    }

    const encoding = e || fh.detectEncoding(decryptedFileContent) ? 'binary' : 'utf8';

    await fh.writeFile(o, decryptedFileContent, encoding);
  }

  async showSecret ({f, p, t}) {
    const ih = new IdentityHelper();

    const identity = await this.openIdentity({f, p});
    const secret = ih.computeSecret(identity.privateKey, t);
    console.log(secret);
  }
}