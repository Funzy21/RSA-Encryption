# RSA-Encryption

## Requirements

### PyCryptodome
[Link to documentation](https://pycryptodome.readthedocs.io/en/latest/src/introduction.html)

We are using the library independent of PyCrypto (pycryptodomex), but it is pretty much the same thing. All modules are installed under the Cryptodome package.

The package can be installed thru the command line via via 

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