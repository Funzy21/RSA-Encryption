from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Cipher import PKCS1_OAEP
import os 

FOLDER_NAME = "RSA_files"

# Generate a new RSA key pair and save it to a file
def genKeypair():

    # Creating a folder to store keys
    if not os.path.exists(FOLDER_NAME):
        os.makedirs(FOLDER_NAME)

    # Generating sender's keys
    sender_key = RSA.generate(2048)
    sender_private_key = sender_key.export_key()
    with open(os.path.join(FOLDER_NAME, "sender_private.pem"), "wb") as f: # .pem (Privacy Enhanced Mail)
        f.write(sender_private_key)
    sender_public_key = sender_key.publickey().export_key()
    with open(os.path.join(FOLDER_NAME, "sender_public.pem"), "wb") as f:
        f.write(sender_public_key) 
         
    # Generating receiver's keys
    receiver_key = RSA.generate(2048)
    receiver_private_key = receiver_key.export_key()
    with open(os.path.join(FOLDER_NAME, "receiver_private.pem"), "wb") as f:
        f.write(receiver_private_key)
    receiver_public_key = receiver_key.publickey().export_key()
    with open(os.path.join(FOLDER_NAME, "receiver_public.pem"), "wb") as f:
        f.write(receiver_public_key)

def encrypt(plaintext, public_key):
    plaintext = plaintext.encode("utf-8")
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(plaintext)

    with open(os.path.join(FOLDER_NAME, "encrypted_data.bin"), "wb") as f:
        f.write(ciphertext)

    return ciphertext

def decrypt(ciphertext, private_key):
    # Read the ciphertext from the file
    with open(ciphertext, "rb") as f:
        ciphertext = f.read()

    # Load the private key
    with open(private_key, "rb") as f:
        private_key = RSA.import_key(f.read())

    # Decrypt the ciphertext
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)

    return plaintext.decode("utf-8")

def addSignature(ciphertext, private_key):
    h = SHA256.new(ciphertext)
    h.update(ciphertext)
    # Signature
    return PKCS1_v1_5.new(private_key).sign(h)

def verifySignature(ciphertext, signature, public_key):
    h = SHA256.new(ciphertext)
    h.update(ciphertext)
    return PKCS1_v1_5.new(public_key).verify(h, signature)

def main():
    message = "CHOVY IS THE GOAT!"
    genKeypair() 

    # Sender
    t = encrypt(message, RSA.import_key(open(os.path.join(FOLDER_NAME, "receiver_public.pem")).read()))
    s = addSignature(t, RSA.import_key(open(os.path.join(FOLDER_NAME, "sender_private.pem")).read()))

    # Receiver
    print(verifySignature(t, s, RSA.import_key(open(os.path.join(FOLDER_NAME, "sender_public.pem")).read()))) # Should return True if working
    d = decrypt(os.path.join(FOLDER_NAME, "encrypted_data.bin"), os.path.join(FOLDER_NAME, "receiver_private.pem"))
    print(d)

if __name__ == "__main__":
    main()