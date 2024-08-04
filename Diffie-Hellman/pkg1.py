import random
import hashlib
from sympy import isprime

# Utility functions
def generate_prime(bits=128):
    while True:
        p = random.getrandbits(bits)
        if isprime(p):
            return p

def generate_random_number(limit):
    return random.randrange(1, limit)

def generate_ibe_keys():
    p = generate_prime()   # A large prime number
    g = generate_random_number(p)  # A generator of the group

    # Master Key Generation
    x = generate_random_number(p)  # Master Secret Key (MSK)
    h = pow(g, x, p)  # h = g^x mod p (Intermediate value)

    # Master Public Key (MPK)
    mpk = (p, g, h)
    msk = x

    return mpk, msk

def save_keys(mpk, msk):
    with open('master_public_key.txt', 'w') as f:
        p, g, h = mpk
        f.write(f'p: {p}\n')
        f.write(f'g: {g}\n')
        f.write(f'h: {h}\n')
    
    with open('master_secret_key.txt', 'w') as f:
        f.write(f'x: {msk}\n')

def main():
    # Generate IBE keys
    mpk, msk = generate_ibe_keys()
    save_keys(mpk, msk)
    print("Master Public Key (MPK) and Master Secret Key (MSK) have been saved to files.")

if __name__ == "__main__":
    main()
