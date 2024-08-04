from Crypto.Hash import SHA256

def read_key(file_path):
    """Read and return the key from a .pem file."""
    with open(file_path, 'rb') as f:
        return int.from_bytes(f.read(), 'big')

def load_public_params():
    """Load and return public parameters from the public_params.pem file."""
    with open('public_params.pem', 'rb') as f:
        p = int.from_bytes(f.read(256), 'big')
        g = int.from_bytes(f.read(256), 'big')
        P = int.from_bytes(f.read(256), 'big')
    return (p, g, P)

def load_master_secret_key():
    """Load and return the master secret key."""
    return read_key('master_secret_key.pem')

def load_private_key(identity):
    """Load and return the private key for a specific identity."""
    return read_key(f'{identity}_private_key.pem')

def derive_symmetric_key(identity, public_params):
    """Derive the symmetric key from the identity and public parameters."""
    identity_hash = SHA256.new(identity.encode()).digest()
    identity_int = int.from_bytes(identity_hash, 'big')

    p, g, P = public_params
    h = pow(g, identity_int, p)
    symmetric_key = SHA256.new(h.to_bytes(256, 'big')).digest()
    return symmetric_key

def display_keys_and_math(identity):
    """Display public parameters, keys, and calculations."""
    # Load keys and parameters
    p, g, P = load_public_params()
    master_secret_key = load_master_secret_key()
    private_key = load_private_key(identity)

    print("Public Parameters:")
    print(f"p (modulus): {p}")
    print(f"g (generator): {g}")
    print(f"P (g^s mod p): {P}")
    
    print("\nMaster Secret Key:")
    print(f"Master secret key: {master_secret_key}")
    
    print(f"\nPrivate Key for Identity '{identity}':")
    print(f"Private key: {private_key}")

    # Demonstrate symmetric key derivation
    symmetric_key = derive_symmetric_key(identity, (p, g, P))
    print("\nDerived Symmetric Key:")
    print(symmetric_key.hex())
    
    # Display some intermediate calculations
    identity_hash = SHA256.new(identity.encode()).digest()
    identity_int = int.from_bytes(identity_hash, 'big')
    h = pow(g, identity_int, p)
    
    print("\nIntermediate Calculations:")
    print(f"Identity hash (SHA256): {identity_hash.hex()}")
    print(f"Identity integer: {identity_int}")
    print(f"Computed h (g^identity_int mod p): {h}")

def main():
    identity = input("Enter the receiver's ID (e.g., email): ")
    
    print("\nDisplaying keys and calculations:")
    display_keys_and_math(identity)

if __name__ == "__main__":
    main()
