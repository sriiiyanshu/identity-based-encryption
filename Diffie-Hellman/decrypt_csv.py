import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def derive_symmetric_key(private_key):
    # Derive a 256-bit AES key from the private key
    key = hashlib.sha256(str(private_key).encode()).digest()
    return key

def decrypt_file(input_file_path, output_file_path, symmetric_key):
    with open(input_file_path, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()
    
    cipher = AES.new(symmetric_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)
    print(f'File decrypted and saved as {output_file_path}')

def main():
    # Take user input for private key
    private_key = int(input("Enter the receiver's private key: "))
    
    # Derive a symmetric key from the private key
    symmetric_key = derive_symmetric_key(private_key)
    
    # Specify the encrypted file path
    input_file_path = 'medical_data_encrypted.csv.enc'
    output_file_path = 'medical_data_decrypted.csv'
    
    # Decrypt the file
    decrypt_file(input_file_path, output_file_path, symmetric_key)
    print(f'Decryption completed for {input_file_path}')

if __name__ == "__main__":
    main()
