import hashlib

# Function to hash the identity
def hash_identity(identity):
    # Hash the identity using SHA-256 and convert to integer
    hash_object = hashlib.sha256(identity.encode())
    hash_hex = hash_object.hexdigest()
    return int(hash_hex, 16)

# Function to derive the public key
def derive_public_key(ID_hash, h, p):
    # Compute the public key as h^ID_hash mod p
    public_key = pow(h, ID_hash, p)
    return public_key

# Function to derive the symmetric key from the public key
def derive_symmetric_key(public_key):
    # Derive a 256-bit AES key using SHA-256 hashing
    symmetric_key = hashlib.sha256(str(public_key).encode()).digest()
    return symmetric_key

# Function to derive the private key
def derive_private_key(ID_hash, g, x, p):
    # Compute the private key as g^(x * ID_hash) mod p
    private_key = pow(g, x * ID_hash, p)
    return private_key

# Input values
identity = "sriyanshu_project@iitg.com"
p = 321796319324557143872102128769093565281
g = 183557242629160796560529301792097754843
h = 138380612142426367059023203844138341442
x = 173485591980486003287672763317672209497

# Calculate the hashed identity
ID_hash = hash_identity(identity)
print(f"Hashed Identity: {ID_hash}")

# Derive the public key using the hashed identity and MPK
public_key = derive_public_key(ID_hash, h, p)
print(f"Public Key for {identity}: {public_key}")

# Derive the symmetric key using the public key
symmetric_key = derive_symmetric_key(public_key)
print(f"Symmetric Key (AES key): {symmetric_key.hex()}")

# Calculate the private key
private_key = derive_private_key(ID_hash, g, x, p)
print(f"Private Key for {identity}: {private_key}")

# Verify the symmetric key derived from the private key matches the one derived from the public key
symmetric_key_from_private_key = derive_symmetric_key(private_key)
print(f"Symmetric Key from Private Key (AES key): {symmetric_key_from_private_key.hex()}")

print(f"Symmetric keys match: {symmetric_key.hex() == symmetric_key_from_private_key.hex()}")
