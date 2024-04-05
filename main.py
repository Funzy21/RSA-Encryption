from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP


# Generate a new RSA key pair and save it to a file
def genKeypair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)
    public_key = key.publickey().export_key()
    with open("receiver.pem", "wb") as f:
        f.write(public_key)

def encrypt(plaintext, public_key):
    plaintext = plaintext.encode("utf-8")
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(plaintext)
    return ciphertext

def decrypt(ciphertext, private_key):
    ciphertext = ciphertext.decode("utf-8")
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext

def addSignature(ciphertext, private_key):
    h = SHA256.new(ciphertext)
    # Signature
    return PKCS1_v1_5.new(private_key).sign(h)

def verifySignature(ciphertext, signature, public_key):
    h = SHA256.new(ciphertext)
    return PKCS1_v1_5.new(public_key).verify(h, signature)


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