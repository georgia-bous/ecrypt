import math
import random
import os
import sympy

from RSA import decrypt_ecb


def generate_prime():  # uses miller rabin, not 100%
    # Generate a random number with 512 bits.
    t = random.getrandbits(2048)  # would be good to assure its big
    p = sympy.nextprime(t)
    return p


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


# Function to check if a number is prime
def is_prime(n):
    if n <= 1:
        return False
    elif n <= 3:
        return True
    elif n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def mod_inverse(a, m):
    x, y, lastx, lasty = 0, 1, 1, 0
    while m:
        a, (q, m) = m, divmod(a, m)
        lastx, x = x, lastx - q * x
        lasty, y = y, lasty - q * y
    return lastx


# Function to pad the message
def pad_message(msg, block_size):
    pad_size = block_size - len(msg) % block_size
    padding = chr(pad_size) * pad_size
    return msg + padding


# Function to unpad the message
def unpad_message(msg):
    padding_size = ord(msg[-1])
    return msg[:-padding_size]


def encrypt_ecb(public_key, msg):
    block_size = int(math.log2(public_key[0])) // 8
    padded_msg = pad_message(msg, block_size)
    blocks = [padded_msg[i:i + block_size] for i in range(0, len(padded_msg), block_size)]
    cipher_blocks = []
    for block in blocks:
        m = int.from_bytes(block.encode(), byteorder='big')
        c = pow(m, public_key[1], public_key[0])
        cipher_blocks.append(c.to_bytes(block_size, byteorder='big'))
    return b''.join(cipher_blocks)


public_key, private_key = generate_keys()
msg = input("Enter the message you want to send: ")
c = encrypt_ecb(public_key, msg)
print("Ciphertext: ", c)
dm = decrypt_ecb(private_key, c)
print("Decrypted message:", dm)
def encrypt_cbc(public_key, msg):
    block_size = int(math.log2(public_key[0])) // 8
    iv = os.urandom(block_size)
    padded_msg = pad_message(msg, block_size)
    blocks = [padded_msg[i:i + block_size] for i in range(0, len(padded_msg), block_size)]
    cipher_blocks = [iv]
    for block in blocks:
        m = int.from_bytes(block.encode(), byteorder='big')
        c = pow(m ^ int.from_bytes(cipher_blocks[-1], byteorder='big'), public_key[1], public_key[0])
        cipher_blocks.append(c.to_bytes(block_size, byteorder='big'))
    return b''.join(cipher_blocks[1:])


def decrypt_cbc(private_key, ciphertext):
    block_size = int(math.log2(private_key[0])) // 8
    iv = os.urandom(block_size)
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext_blocks = []
    for i, block in enumerate(blocks):
        c = int.from_bytes(block, byteorder='big')
        m = pow(c, private_key[1], private_key[0]) ^ int.from_bytes(iv if i == 0 else blocks[i - 1], byteorder='big')
        plaintext_blocks.append(m.to_bytes(block_size, byteorder='big'))
    return unpad_message(b''.join(plaintext_blocks))