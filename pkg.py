# keygen.py
from Crypto.PublicKey import DSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

def generate_key_pair():
    key = DSA.generate(2048)
    private_key = key
    public_key = key.publickey()
    return private_key, public_key

def generate_master_key_and_params():
    master_key, master_public_key = generate_key_pair()
    p = master_public_key.p
    g = master_public_key.g
    h = master_public_key.y
    s = master_key.x
    P = pow(g, s, p)
    return (p, g, P), s

def save_keys(params, master_secret_key):
    with open('public_params.pem', 'wb') as f:
        f.write(params[0].to_bytes(256, 'big'))
        f.write(params[1].to_bytes(256, 'big'))
        f.write(params[2].to_bytes(256, 'big'))

    with open('master_secret_key.pem', 'wb') as f:
        f.write(master_secret_key.to_bytes(256, 'big'))

def main():
    params, master_secret_key = generate_master_key_and_params()
    save_keys(params, master_secret_key)
    print("Public parameters and master secret key generated and saved.")

if __name__ == "__main__":
    main()
