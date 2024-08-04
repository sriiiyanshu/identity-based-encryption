# decryption.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256
import os

def derive_symmetric_key(identity, public_params):
    identity_hash = SHA256.new(identity.encode()).digest()
    identity_int = int.from_bytes(identity_hash, 'big')

    p, g, P = public_params
    h = pow(g, identity_int, p)
    symmetric_key = SHA256.new(h.to_bytes(256, 'big')).digest()
    return symmetric_key

def decrypt_file(input_file_path, output_file_path, identity):
    with open(input_file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    with open('public_params.pem', 'rb') as f:
        p = int.from_bytes(f.read(256), 'big')
        g = int.from_bytes(f.read(256), 'big')
        P = int.from_bytes(f.read(256), 'big')
    
    public_params = (p, g, P)
    symmetric_key = derive_symmetric_key(identity, public_params)

    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv=iv)
    try:
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except ValueError:
        print("Decryption failed. Padding is incorrect or key is wrong.")
        return
    
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)

    print(f'File decrypted and saved as {output_file_path}')

def main():
    identity = input("Enter the receiver's ID (e.g., email): ")
    input_file_path = 'medical_data.csv.enc'
    output_file_path = 'medical_data_decrypted.csv'  # Save decrypted content to a new file
    decrypt_file(input_file_path, output_file_path, identity)

if __name__ == "__main__":
    main()
