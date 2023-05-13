import math
import random

import sympy


# Function to generate a prime number
def generate_prime():  # uses miller rabin, not 100%
    # Generate a random number with 512 bits.
    t = random.getrandbits(1024)  # would be good to assure its big
    p = sympy.nextprime(t)
    return p


# Function to generate the public and private keys
def generate_keys():
    # Generate two large prime numbers
    p = generate_prime()
    q = generate_prime()

    # Calculate n and phi(n)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose a random number e that is coprime to phi(n)
    e = random.randrange(1, phi)
    g = math.gcd(e, phi)
    while g != 1:
        e = random.randrange(1, phi)
        g = math.gcd(e, phi)

    # Calculate the modular multiplicative inverse of e modulo phi(n)
    d = mod_inverse(e, phi)

    # Return the public and private keys
    return (n, e), (n, d)


# Function to calculate the modular multiplicative inverse of a modulo m using the extended Euclidean algorithm
def mod_inverse(a, m):
    # Compute the modular inverse of a modulo m using the extended Euclidean algorithm
    x, y, lastx, lasty = 0, 1, 1, 0
    while m:
        a, (q, m) = m, divmod(a, m)
        lastx, x = x, lastx - q * x
        lasty, y = y, lasty - q * y
    return lastx


# Function to pad the message
def pad_message(msg, block_size):
    pad_size = block_size - len(msg) % block_size
    padding = bytes([pad_size] * pad_size)
    return msg + padding


def unpad_message(msg):
    padding_size = msg[-1]
    return msg[:-padding_size]


def encrypt_ecb(public_key, msg):
    block_size = (public_key[0].bit_length() + 7) // 8
    padded_msg = pad_message(msg.encode(), block_size)
    blocks = [padded_msg[i:i + block_size] for i in range(0, len(padded_msg), block_size)]
    cipher_blocks = []
    for block in blocks:
        m = int.from_bytes(block, byteorder='big')
        c = pow(m, public_key[1], public_key[0])
        cipher_blocks.append(c.to_bytes(block_size, byteorder='big'))
    return b''.join(cipher_blocks)


def decrypt_ecb(private_key, ciphertext):
    block_size = (private_key[0].bit_length() + 7) // 8
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext_blocks = []
    for block in blocks:
        c = int.from_bytes(block, byteorder='big')
        m = pow(c, private_key[1], private_key[0])
        plaintext_blocks.append(m.to_bytes(block_size, byteorder='big'))
    plaintext = unpad_message(b''.join(plaintext_blocks))
    return plaintext.decode()


public_key, private_key = generate_keys()
msg = input("Enter the message you want to send: ")
c = encrypt_ecb(public_key, msg)
print("Ciphertext: ", c)
dm = decrypt_ecb(private_key, c)
print("Decrypted message:", dm)
