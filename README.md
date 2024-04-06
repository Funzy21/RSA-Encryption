# RSA-Encryption

This program implements RSA-OAEP encryption with separate key pairs for encryption and signing, along with the encrypt-then-sign and verify-then-decrypt scheme for authenticated encryption. 

### Key Features:

**Key Pair Generation**: The program can generate new RSA key pairs for encryption and signing using the `genKeypairs()` function.

**Encrypt-then-Sign**: The program encrypts messages using RSA-OAEP encryption along with a receiver's public key, and then signs the ciphertext using digital signatures. The `encrypt()` function handles the encryption, while the `addSignature()` function adds the digital signature to the encrypted data while utilizing the SHA256 hashing algorithm. 

**Verify-then-Decrypt**: Upon receiving a signed ciphertext, the program verifies the signature using the sender's public key before decrypting the message. The `verifySignature()` function verifies the signature, and the `decrypt()` function decrypts the message if the signature is valid.

**Simulate Incorrect Verification Key**: Lastly, the program also allows simulating using an incorrect verification key to demonstrate that if an incorrect verification key is used, the program will fail to verify the signature, indicating that we can’t be sure if the message is correct/real or not.

### Usage

**Generating Key Pairs**: A user can generate new key pairs by selecting the "Generate new key pairs" option. This creates separate key pairs for encryption and signing and stores them in the "keys" directory.

**Encrypting and Signing Messages**: A user can enter a message to encrypt and sign using the "Encrypt and Sign Message" option. The program encrypts the message using the recipient's public key, adds a digital signature using the sender's private key, and saves the encrypted data and signature files.

**Verifying Signatures and Decrypting Messages**: A user can verify signatures and decrypt messages using the "Verify signature and Decrypt Message" option. The program verifies the signature using the sender's public key and decrypts the message if the signature is valid.

**Simulating Incorrect Verification Key**: A user can also simulate using an incorrect verification key using the "Simulate using an incorrect verification key" option.

## Requirements

### PyCryptodome
[Link to documentation](https://pycryptodome.readthedocs.io/en/latest/src/introduction.html)

We are using the library independent of PyCrypto (pycryptodomex), but it is pretty much the same thing. All modules are installed under the Cryptodome package. 

This library has pretty much most of what we need for cryptographic operations. The packages used granted us plenty of tools to work with. Signing and verification were very straightforward following the documentation for the *Cryptodome.Signature* package. OAEP and SHA256 hashing were also implemented through the methods in their respective packages (and ofc by following some examples in the docs!). 

With that being said, the package can be installed thru the command line via

pip:
```
pip install pycryptodomex
```

To test if everything is working:
```
pip install pycryptodome-test-vectors
python -m Cryptodome.SelfTest
```

Without pip (Linux):
```
sudo apt-get update -y
sudo apt-get install -y python3-pycryptodome
```

## Running the program

Open up a terminal in the repo's directory and simply:
```
python main.py
```

The program will give the user some operations. Simply input the number and whatever follows. A sample message input is already provided beforehand in *message.txt*. It is also already encoded and signed, so you should be able to use the verification-decryption operation right away.

Feel free to overwrite the contents of *message.txt* via the second operation (or directly). 