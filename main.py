from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Cipher import PKCS1_OAEP


# Generate a new RSA key pair and save it to a file
def genKeypair():
    # Generating sender's keys
    sender_key = RSA.generate(2048)
    sender_private_key = sender_key.export_key()
    with open("sender_keys/private.pem", "wb") as f:
        f.write(sender_private_key)
    sender_public_key = sender_key.publickey().export_key()
    with open("sender_keys/sender.pem", "wb") as f:
        f.write(sender_public_key)
    # Generating receiver's keys
    receiver_key = RSA.generate(2048)
    receiver_private_key = receiver_key.export_key()
    with open("receiver_keys/private.pem", "wb") as f:
        f.write(receiver_private_key)
    receiver_public_key = receiver_key.publickey().export_key()
    with open("receiver_keys/receiver.pem", "wb") as f:
        f.write(receiver_public_key)

def encrypt(plaintext, public_key):
    plaintext = plaintext.encode("utf-8")
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(plaintext)
    with open ("encrypted_data.bin", "wb") as f:
        f.write(ciphertext)
    return ciphertext

def decrypt(ciphertext, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext

def addSignature(ciphertext, private_key):
    h = SHA256.new(ciphertext)
    h.update(ciphertext)
    # Signature
    return PKCS1_v1_5.new(private_key).sign(h)

def verifySignature(ciphertext, signature, public_key):
    h = SHA256.new(ciphertext)
    h.update(ciphertext)
    return PKCS1_v1_5.new(public_key).verify(h, signature)


# PLAYGROUND

message = "Hello this is a test message."
t = encrypt(message, RSA.import_key(open("receiver_keys/receiver.pem").read()))
s = addSignature(t, RSA.import_key(open("sender_keys/private.pem").read()))

# genKeypair() -> Uncomment to generate keypairs in your directories
#print(verifySignature(t, s, RSA.import_key(open("sender_keys/sender.pem").read()))) # Should return True if working

d = decrypt(t, RSA.import_key(open("receiver_keys/private.pem").read()))
print(d.decode("utf-8"))