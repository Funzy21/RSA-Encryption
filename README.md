# Machine Problem 2: RSA-Encryption

## Requirements

### PyCryptodome
[Link to documentation](https://pycryptodome.readthedocs.io/en/latest/src/introduction.html)

We are using the library independent of PyCrypto. All modules are installed under the Cryptodome package.

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

W/O pip (Ubuntu):
```
sudo apt-get update -y
sudo apt-get install -y python3-pycryptodome
```