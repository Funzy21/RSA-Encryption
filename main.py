from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Cipher import PKCS1_OAEP
import os

SENDER_KEYS_FOLDER_NAME = "sender_keys"
RECEIVER_KEYS_FOLDER_NAME = "receiver_keys"

def genMessage(message):
    with open("message.in", "w") as f:
        f.write(message)
        
# Every time this function is called, new keypairs are generated
def genKeypair():
    # Create sender and receiver keys folder if it doesn't exist
    if not os.path.exists(SENDER_KEYS_FOLDER_NAME):
        os.makedirs(SENDER_KEYS_FOLDER_NAME)
    if not os.path.exists(RECEIVER_KEYS_FOLDER_NAME):
        os.makedirs(RECEIVER_KEYS_FOLDER_NAME)

    # Generating sender's keys
    sender_key = RSA.generate(2048)
    sender_private_key = sender_key.export_key()
    with open(os.path.join(SENDER_KEYS_FOLDER_NAME, "private.pem"), "wb") as f:
        f.write(sender_private_key)
    sender_public_key = sender_key.publickey().export_key()
    with open(os.path.join(SENDER_KEYS_FOLDER_NAME, "sender.pem"), "wb") as f:
        f.write(sender_public_key)
        
    # Generating receiver's keys
    receiver_key = RSA.generate(2048)
    receiver_private_key = receiver_key.export_key()
    with open(os.path.join(RECEIVER_KEYS_FOLDER_NAME, "private.pem"), "wb") as f:
        f.write(receiver_private_key)
    receiver_public_key = receiver_key.publickey().export_key()
    with open(os.path.join(RECEIVER_KEYS_FOLDER_NAME, "receiver.pem"), "wb") as f:
        f.write(receiver_public_key)

def encrypt(plaintext, public_key):
    with open("message.in", "r") as f:
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
        print("2. Encrypt message")
        print("3. Decrypt message")
        print("4. Add signature")
        print("5. Verify signature")
        print("6. Exit")
        choice = input("Select Operation: ")
        
        if choice == "1":
            print("Generating new keypairs...")
            genKeypair()
            os.system("cls")
            print("\nKeypairs generated successfully.\n")
            
        elif choice == "2":
            message = input("Enter the message: ")
            genMessage(message)
            t = encrypt(message, RSA.import_key(open(os.path.join(RECEIVER_KEYS_FOLDER_NAME, "receiver.pem")).read()))
            print("\nSuccessfully encrypted message.\n")
            
        elif choice == "3":
            d = decrypt(t, RSA.import_key(open(os.path.join(RECEIVER_KEYS_FOLDER_NAME, "private.pem")).read()))
            print(d.decode("ascii") + "\n")
            
        elif choice == "4":
            s = addSignature(t, RSA.import_key(open(os.path.join(SENDER_KEYS_FOLDER_NAME, "private.pem")).read()))
            print(s)
            print()
            
        elif choice == "5":
            if verifySignature(t, s, RSA.import_key(open(os.path.join(SENDER_KEYS_FOLDER_NAME, "sender.pem")).read())):
                print("\nSignature verification successful.\n")
            else:
                print("\nSignature verification failed.\n")
               
        elif choice == "6":
            break
            
        else:
            print("\nInvalid choice. Please try again.\n")

if __name__ == "__main__":
    main()