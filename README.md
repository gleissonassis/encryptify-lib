# encryptif-cli

This is a proposal tool for a future service called Encryptify. The main goal is provide a tool to exchange files and messages in a encrypted and secure way. It is a CLI (command line interface) to created identities (private and public key encrypted file), encrypt and decrypt files and messages.

## Installing the CLI

You can clone the code or install it directly via npm as a global package.

```sh
npm install -g encryptify-cli
```
### Tutorial

To prepare your machine to run the commands, please create a **tmp** folder in your current directory and a sample file as well.

```sh
mkdir tmp
echo "this is a important file" > sample.txt
````

The **tmp** directory will store the identity files and the encrypted file.

#### Identity file

To start using **encrypify-cli** you need to create the identity file. 

```sh
encryptify-cli -a generate -f ./tmp/1.id -p 123456
```

If necessary you can show the file content using **show** action.
```sh
encryptify-cli -a show -f ./tmp/1.id -p 123456
{
  address: '0x7B02db9D047F6e3A99a9Bbc12bB9fc003270EA64',
  privateKey: '0x36d364966a0675354fdf7a932d63f20bf0c9b8fa86e1dfcb40b63ee8f76068a4',
  publicKey: 'bd176d46b0f1aa0a06fd8bd8bbf908406b7ab864b3d49279f26eb0a618eeebeb3505905147c36d39d1bf0ff168a3c6df07ba32c9ce3b3f8ff3fe5abafe93c144',
  compressedPublicKey: '02bd176d46b0f1aa0a06fd8bd8bbf908406b7ab864b3d49279f26eb0a618eeebeb'
}
```

The important information in this file is the private key, however we pre compute the public key, the address (using Ethereum format) and the compressed public key which is the best way to identity you than public key to short message channels.

To follow the complete tutorial please generate a second identity file.

```sh
encryptify-cli -a generate -f ./tmp/2.id -p 123456
```

You can see the file content as well.
```sh
encryptify-cli -a show -f ./tmp/2.id -p 123456
{
  address: '0xDb8cEB661ec089fFe75318687B328eE628Af8D7a',
  privateKey: '0x34df7602ffa0822e19bc7881a726772f633e89003d400b2218c7890a30f086c1',
  publicKey: '0ec055aa2c6724452fc3c4ae76271af93be3664c40e103045ba5cccfcd147903f8a6fe8d85343f8114674137c92c0f39411c43b5a559669de2e06625190d3c87',
  compressedPublicKey: '030ec055aa2c6724452fc3c4ae76271af93be3664c40e103045ba5cccfcd147903'
}
```

If you open directly the files in your editor you will see something like this:

1.id
```
11c0806e02247fd945c308575c98db6e9a57cf597153390e410c7d5abcec36e1797835ccba25b5839117c9bb871648fd143b15775f6c7e1c69182516c042a05d16035692a05c24204dd98c83ade9c492adbb3d987dc2006bc2ca066399fab5b2bebc9a0239b53dfc6d5a488a91d0fb45ca0b72408fd7a8418ed4bb74ab7a22afba9dd6120bfed5d1d4e2a516dacf29bcd6d2d38ab4036875240d8c4b2666fab8d8949fa73f4181c1687216f66fd8c4d855fbb0ace2a19e28d4f8a6e6e1219146aac980a105e64c0b2aa66cc044b336c471d9d34364b0d16cbe6f43ac6840549e76b51ff1e2faea882a33833345609536c0ec199b5aa063bd5ec464c4f5c857ea5df39c3e2ee2752123d016d26bc33069778a1f542b3e22005fbeef297336e88c1cb7680df95f54caf84f8dfc3dbdda30e5fad530543500f581b0548564d0569e51f6a0a29804ddfd706609eb69b56ed9e3a6e82e9be0850278023482a498233650cdb808032450c94c9617311f6a0ad603fd9585d407bdc1b540328d47b50eeb6347685af5df47c760023623731fd26bb27ff7f569eaef651c69b089a81378df4b7dbf1343564befd7ccfa1299d780d28d9038f5945faec3ab0b81eac0e31230c562767963d46777081b412c218d5e19cf06e559
```

2.id
```
44d57a1e91dba46b389e0cf6c2482518fe660359849613f4f7ecc3480631d78fa19c0b359715d389cc1cc375dfb3102b644823fcb423565cefcfa6cfb35ee1f7aeb99fe17e1c95b0ad8d90a5dde6b29c2df56c027d27b2bbab6d62881a5d86655368a32751b2b9343112814810a0742d84409f4f29721933a403faffc54ea3efb1c2946948a38e0cd2e4b1042b3f0a4b19bbeff850050458c38c5e54ee3dd991a41ecdc5c3fceb60eaec7be243dfdaa48b17a982646093088236c1362f45b6187b6b4b92744183fecc8bd4b229a80dfb66cb1fa8cf66305d90d79d37117aba9a506a0a48a37f9647d4fe30751bfa8dc4e6c4b39623e3bb6e2fb63528f158aa03de1478bba7d91a7c0fbf7fd2e582712d4732c43e92762a3b8f48e09a44131af27b7b4a302e3b90e234647354529c60c24f980338ed74f95f8afa53cabc90b16a6dc5eb0b76960ee2a3702379fe1652822733d33299a2d1b1fabe8fb1821b3bdd281fb376de3651b5449fd5e663a9720934491d45c351e6053c468cc951a05c80adbc1196217ac5e0334e70c44347ab8f9a2a3cd6aed1114aea711546b84102e0f41a516441d1e20fe1eeec0dbfbe1ad13d2550409931c8f4c367a5cfb18f34b6d05135cb75a01c013ad562279c7d307c293c2344
```

#### Encrypting messages

To encrypt a message you can use your identity file and specify a message using the parameter **-m**.

```sh
encryptify-cli -a encrypt -f ./tmp/1.id -p 123456 -m message
v5WMfrG8sn1OwBUHOIpfPALzu05YJPaJYaqCawm1nKF5mQcvvdHuoMrnixMbJOXRiUwhHD5cWym7vwmZ+7g/IOfAR88NCrUF8m8vE70XPCnJt+7YeyyRI0TX31Tw0OeY5w==
```

You can run the **decrypt** action specifying the encryted message in the **-m** parameter.

```sh
encryptify-cli -a decrypt -f ./tmp/1.id -p 123456 -m v5WMfrG8sn1OwBUHOIpfPALzu05YJPaJYaqCawm1nKF5mQcvvdHuoMrnixMbJOXRiUwhHD5cWym7vwmZ+7g/IOfAR88NCrUF8m8vE70XPCnJt+7YeyyRI0TX31Tw0OeY5w==
```

You can encrypt the message by using a secure channel beteween two accounts by specifying a target (**-t** paramter). Using this feature **encryptify-cli** will compute a secret using the [Diffie–Hellman key exchange method](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange). In a simple way the secret will be computed using the pair private key and target public key, so you will need the target public key (provided by whom you want to exchange data) and your private key contained in the identiy file, to decrypt the message the other party will use his/her private key and your know public key.

To show how to use this method consider the two identity files created before and the compressed public key (or the public key):

```sh
encryptify-cli -a encrypt -f ./tmp/1.id -p 123456 -m message -t 030ec055aa2c6724452fc3c4ae76271af93be3664c40e103045ba5cccfcd147903
9ef36a45e2ba5bd74418ea2362ce0f43d08ac2d67da2924533c3ae2c6f485c67522c417d278960217d9b98aa3c95b64883633f5d8cd65b7e018f271521bdd314f64c169e0a3c4e7e05248a08643cac521dad1ccc14eeb049d39c7af7ce877da4218b0b406044c0
````

To decrypt the message:
```sh
encryptify-cli -a decrypt -f ./tmp/2.id -p 123456 -m 9ef36a45e2ba5bd74418ea2362ce0f43d08ac2d67da2924533c3ae2c6f485c67522c417d278960217d9b98aa3c95b64883633f5d8cd65b7e018f271521bdd314f64c169e0a3c4e7e05248a08643cac521dad1ccc14eeb049d39c7af7ce877da4218b0b406044c0 -t 02bd176d46b0f1aa0a06fd8bd8bbf908406b7ab864b3d49279f26eb0a618eeebeb
```

As you can see the first command encrypts the message using the first private key identity file and a target public key, in order to decrypt the message the target, using the second identity file, uses the first public key as the target account.

#### Encrypting files

In the same way, you can encrypt/decrypt files by specifying the source (**-s parameter**) and the output path (**-o parameter**)

```sh
encryptify-cli -a encrypt -f ./tmp/1.id -p 123456 -s ./sample.txt -o ./tmp/sample.txt.encryptify
encryptify-cli -a decrypt -f ./tmp/1.id -p 123456 -s ./tmp/sample.txt.encryptify -o ./tmp/sample.txt 
```

Or using a target account:

```sh
encryptify-cli -a encrypt -f ./tmp/1.id -p 123456 -s ./sample.txt -o ./tmp/sample.txt.encryptify -t 030ec055aa2c6724452fc3c4ae76271af93be3664c40e103045ba5cccfcd147903
encryptify-cli -a decrypt -f ./tmp/1.id -p 123456 -s ./tmp/sample.txt.encryptify -o ./tmp/sample.txt -o ./tmp/package.json -t 02bd176d46b0f1aa0a06fd8bd8bbf908406b7ab864b3d49279f26eb0a618eeebeb
```

#### Computed secret key

You can show the computed secret key in the [Diffie–Hellman key exchange method](https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange) running this command:

```sh
encryptify-cli -a secret -f ./tmp/1.id -p 123456 -t 030ec055aa2c6724452fc3c4ae76271af93be3664c40e103045ba5cccfcd147903
encryptify-cli -a secret -f ./tmp/2.id -p 123456 -t 02bd176d46b0f1aa0a06fd8bd8bbf908406b7ab864b3d49279f26eb0a618eeebeb
```

This commands must show the same computed key.


### Parameters

- -a: an action (generate, open, encrypt, decrypt and secret).
- -f: the identity file path.
- -p: the password to encrypt/decrypt the identity file.
- -m: a string message to be encrypted or a encrypted message tbe decrypted.
- -t: the target public key account.
- -s: the source file (to be encrypted or a encrypted file).
- -o: the output file (a decrypted file or a encrypted file).
