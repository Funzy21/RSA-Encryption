from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Cipher import PKCS1_OAEP
import os

def genMessage(message):
    with open("message.txt", "w") as f:
        f.write(message)
        
# Every time this function is called, new keypairs are generated
def genKeypairs():
    if not os.path.exists("keys"):
        os.makedirs("keys")
    
    # Generating encryption key-pair
    encryption_key = RSA.generate(2048)
    private = encryption_key.export_key()
    with open(os.path.join("keys","enc_private.pem"), "wb") as f:
        f.write(private)
    public = encryption_key.publickey().export_key()
    with open(os.path.join("keys","enc_public.pem"), "wb") as f:
        f.write(public)
        
    # Generating signing key-pair
    signing_key = RSA.generate(2048)
    signing = signing_key.export_key()
    with open(os.path.join("keys","signing.pem"), "wb") as f:
        f.write(signing)
    verifying = signing_key.publickey().export_key()
    with open(os.path.join("keys","verifying.pem"), "wb") as f:
        f.write(verifying)
        
def encrypt(plaintext, public_key):
    with open("message.txt", "r") as f:
        plaintext = f.read()
    plaintext = plaintext.encode("ascii")
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(plaintext)
    with open("encrypted_data.bin", "wb") as f:
        f.write(ciphertext)
    return ciphertext

def decrypt(ciphertext, private_key):
    with open("encrypted_data.bin", "rb") as f:
        ciphertext = f.read()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    plaintext = cipher_rsa.decrypt(ciphertext)
    return plaintext

def addSignature(ciphertext, private_key):
    h = SHA256.new(ciphertext)
    h.update(ciphertext)
    # Signature
    return PKCS1_v1_5.new(private_key).sign(h)

# Receiver verifies the signature using the sender's public key
def verifySignature(ciphertext, signature, public_key):
    h = SHA256.new(ciphertext)
    h.update(ciphertext)
    return PKCS1_v1_5.new(public_key).verify(h, signature)

# PLAYGROUND
def main():
    while True:
        print("1. Generate new keypairs")
        print("2. Encrypt and Sign Message")
        print("3. Verify signature and Decrypt Message")
        print("4. Exit")
        choice = input("Select Operation: ")
        
        if choice == "1":
            print("Generating new keypairs...")
            genKeypairs()
            os.system("cls")
            print("\nKeypairs generated successfully.\n")
            
        elif choice == "2":
            message = input("Enter the message: ")
            genMessage(message)
            t = encrypt(message, RSA.import_key(open(os.path.join("keys", "enc_public.pem")).read()))
            s = addSignature(t, RSA.import_key(open(os.path.join("keys", "signing.pem")).read()))
            print("\nSuccessfully encrypted message.\n")
            print(s)
            
        elif choice == "3":
            if verifySignature(t, s, RSA.import_key(open(os.path.join("keys", "verifying.pem")).read())):
                print("\nSignature verification successful.\n")
                d = decrypt(t, RSA.import_key(open(os.path.join("keys", "enc_private.pem")).read()))
                print(d.decode("ascii") + "\n")
            else:
                print("\nSignature verification failed.\n")
               
        elif choice == "4":
            break
            
        else:
            print("\nInvalid choice. Please try again.\n")

if __name__ == "__main__":
    main()