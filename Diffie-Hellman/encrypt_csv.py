import hashlib
import os
import pandas as pd
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Utility functions
def hash_identity(identity):
    # Hash the identity using SHA-256 and convert to integer
    hash_object = hashlib.sha256(identity.encode())
    hash_hex = hash_object.hexdigest()
    return int(hash_hex, 16)

def load_keys():
    with open('master_public_key.txt', 'r') as f:
        lines = f.readlines()
        p = int(lines[0].split(': ')[1])
        g = int(lines[1].split(': ')[1])
        h = int(lines[2].split(': ')[1])

    return (p, g, h)

def derive_symmetric_key(identity, mpk):
    p, g, h = mpk
    ID_hash = hash_identity(identity)
    # Compute the public key as h^ID_hash mod p
    public_key = pow(h, ID_hash, p)
    # Derive a 256-bit AES key from the public key
    key = hashlib.sha256(str(public_key).encode()).digest()
    return key

def encrypt_file(input_file_path, output_file_path, symmetric_key):
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()
    
    cipher = AES.new(symmetric_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    with open(output_file_path, 'wb') as f:
        f.write(cipher.iv + ciphertext)
    print(f'File encrypted and saved as {output_file_path}')

def main():
    # Load MPK
    mpk = load_keys()
    
    # Take user input for receiver's ID
    receiver_id = input("Enter the receiver's ID (e.g., email): ")
    
    # Derive a symmetric key from the receiver's identity and MPK
    symmetric_key = derive_symmetric_key(receiver_id, mpk)
    
    # Specify the CSV file path
    input_file_path = 'medical_data.csv'
    output_file_path = 'medical_data_encrypted.csv.enc'
    
    # Encrypt the CSV file
    encrypt_file(input_file_path, output_file_path, symmetric_key)
    print(f'Encryption completed for {input_file_path}')

if __name__ == "__main__":
    main()
