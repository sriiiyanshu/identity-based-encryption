import hashlib

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
    
    with open('master_secret_key.txt', 'r') as f:
        x = int(f.readline().split(': ')[1])

    return (p, g, h), x

def generate_private_key(identity, mpk, msk):
    p, g, h = mpk
    # Hash the identity to get a numeric value
    ID_hash = hash_identity(identity)
    
    # Compute the private key as g^(x * ID_hash) mod p
    private_key = pow(g, msk * ID_hash, p)
    return private_key

def save_private_key(identity, private_key):
    filename = f'private_key_{identity}.txt'
    with open(filename, 'w') as f:
        f.write(f'Private Key for {identity}: {private_key}\n')

def main():
    # Load MPK and MSK
    mpk, msk = load_keys()

    # Take user input
    email_id = input("Enter your email ID (or alphanumeric identity): ")
    
    # Generate and save private key
    private_key = generate_private_key(email_id, mpk, msk)
    
    # Display the private key
    print(f"Private Key for {email_id}: {private_key}")
    
    # Save the private key to a file
    save_private_key(email_id, private_key)
    print(f"Private Key for {email_id} has been saved to file.")

if __name__ == "__main__":
    main()
