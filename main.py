from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP


def encrypt(plaintext: str, public_key: RSA.RsaKey):
    plaintext = plaintext.encode("utf-8")
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(plaintext)
    return ciphertext

# Encryption based on docs
"""
message = "Hello this is a test message.".encode("utf-8")

recipient_key = RSA.import_key(open("receiver.pem").read())
session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key

cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key

cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(message)

with open("encrypted_data.bin", "wb") as f:
    f.write(enc_session_key)
    f.write(cipher_aes.nonce)
    f.write(tag)
    f.write(ciphertext)
"""

# Decryption based on docs
"""
private_key = RSA.import_key(open("private.pem").read())

with open("encrypted_data.bin", "rb") as f:
    enc_session_key = f.read(private_key.size_in_bytes())
    nonce = f.read(16)
    tag = f.read(16)
    ciphertext = f.read()

# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
print(data.decode("utf-8"))

"""

# Generate a new RSA key pair and save it to a file
def genRSA(code: str):
    key = RSA.generate(bits = 3072)
    encrypted_key = key.export_key(passphrase=code, pkcs=8,
                                  protection="scryptAndAES128-CBC",
                                  prot_params={'iteration_count':131072})
    with open("rsa_key.bin", "wb") as f:
        f.write(encrypted_key)
    print(key.publickey().export_key())

# Method to generate a new RSA key pair and save it to a file
def genKeypair():
    key = RSA.generate(bits = 2048)
    private_key = key.export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)
    public_key = key.publickey().export_key()
    with open("receiver.pem", "wb") as f:
        f.write(public_key)
# Pad plaintext and add randomness (via hashing and XOR)
def padding(plaintext: str):
    return plaintext.encode()

# Sign an encrypted message
def addSignature(message:str):
    key = RSA.import_key(open("receiver.pem").read())
    h = SHA256.new(message)
    signature = PKCS1_v1_5.new(key).sign(h)
    PKCS1_v1_5.new(key).verify(h, signature)

def decrypt(ciphertext: str):
    # TODO: Decrypt the ciphertext using RSA-OAEP
    pass
