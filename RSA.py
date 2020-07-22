from maths import *
import random

"""
A standard implementation of the RSA2 Algorithm using 64 - bit primes, and RSA1 using .
An integer of maximum around 122 - bits can be safely encrypted using this implementation.
Public and private keys are conjugate pairs.
If one is used for encryption, other is used for decryption and vice-versa.
"""

def generate_keysRSA1():
    p = q = 1
    # generating two prime numbers p and q of max 56 - bit
    while not miller_rabin(p):
        p = random.randrange(pow(2, 55) + 1, pow(2, 56), 2)
    while not miller_rabin(q):
        q = random.randrange(pow(2, 55) + 1, pow(2, 56), 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    while True:
        e = random.randrange(2, phi_n)
        gcd, d, temp = extended_euclid(e, phi_n)
        if gcd == 1 and d > 0:
            break
    public_key = [e, n]
    private_key = [d, n]
    return public_key, private_key


def generate_keysRSA2():
    p = q = 1
    # generating two prime numbers p and q of max 64 - bit
    while not miller_rabin(p):
        p = random.randrange(pow(2, 63) + 1, pow(2, 64), 2)
    while not miller_rabin(q):
        q = random.randrange(pow(2, 63) + 1, pow(2, 64), 2)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    while True:
        e = random.randrange(2, phi_n)
        gcd, d, temp = extended_euclid(e, phi_n)
        if gcd == 1 and d > 0:
            break
    public_key = [e, n]
    private_key = [d, n]
    return public_key, private_key


# Encryption and Decryption are identical for RSA.
def encrypt(data, key):
    return mod_exponent(data, key[0], key[1])


def decrypt(data, key):
    return mod_exponent(data, key[0], key[1])


# Usage / Testing RSA :-
if __name__ == "__main__":
    public, private = generate_keysRSA2()
    plain_text = random.randrange(1 << 120)
    print("PlainText  -> " + str(plain_text))

    cipher_text = encrypt(plain_text, public)
    print("CipherText -> " + str(cipher_text))

    recovered_text = decrypt(cipher_text, private)
    print("RecoveredText -> " + str(recovered_text))
