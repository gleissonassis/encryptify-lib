import fs from 'fs';
import { getEncoding } from 'istextorbinary';
import isBinaryPath from 'is-binary-path';

export default class FileHelper {
  openFile (path, encoding) {
    return new Promise((resolve, reject) => {
      fs.readFile(path, encoding, (err,data) => {
        if (err) {
          reject(err);
        }
        resolve(data);
      });
    });
  }

  writeFile (path, content, encoding) {
    return new Promise((resolve, reject) => {
      fs.writeFile(path, content, {encoding}, function (err) {
        if (err) return reject(err);
        resolve();
      });
    });
  }

  detectEncoding (buffer) {
    return getEncoding(buffer);
  }

  isBinaryPath (path) {
    return isBinaryPath(path);
  }
}