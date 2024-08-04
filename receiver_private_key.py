# key_extraction.py
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256

def extract_private_key(identity, master_secret_key):
    identity_hash = SHA256.new(identity.encode()).digest()
    identity_int = int.from_bytes(identity_hash, 'big')

    private_key = (identity_int * master_secret_key) % (2**2048 - 1)
    return private_key

def save_private_key(identity, private_key):
    with open(f'{identity}_private_key.pem', 'wb') as f:
        f.write(private_key.to_bytes(256, 'big'))

def main():
    identity = input("Enter the receiver's ID (e.g., email): ")
    with open('master_secret_key.pem', 'rb') as f:
        master_secret_key = int.from_bytes(f.read(), 'big')

    private_key = extract_private_key(identity, master_secret_key)
    save_private_key(identity, private_key)
    print(f"Private key for {identity} generated and saved.")

if __name__ == "__main__":
    main()
