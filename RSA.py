import math
import random
import os

# Function to generate a prime number
def generate_prime():
    # Generate a random number with 256 bits
    t = random.getrandbits(256)
    p = 2 * t + 1
    while not is_prime(p):
        t = t + 1
        p = 2 * t + 1
    return p


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
    return ((n, e), (n, d))


# Function to calculate the modular multiplicative inverse of a modulo m using the extended Euclidean algorithm
def mod_inverse(a, m):
    r1, r2 = a, m
    s1, s2 = 1, 0
    while r2 > 0:
        q = r1 // r2
        r1, r2 = r2, r1 - q * r2
        s1, s2 = s2, s1 - q * s2
    return s1 % m


# Function to pad the message
def pad_message(msg, block_size):
    pad_size = block_size - len(msg) % block_size
    padding = chr(pad_size) * pad_size
    return msg + padding

# Function to unpad the message
def unpad_message(msg):
    padding_size = ord(msg[-1])
    return msg[:-padding_size]

# Function to unpad the message
def unpad_message(msg):
    padding_size = ord(msg[-1])
    return msg[:-padding_size]


# Function to encrypt a message using ECB mode
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


def decrypt_ecb(private_key, ciphertext):
    block_size = int(math.log2(private_key[0])) // 8
    blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
    plaintext_blocks = []
    for block in blocks:
        c = int.from_bytes(block, byteorder='big')
        m = pow(c, private_key[1], private_key[0])
        plaintext_blocks.append(m.to_bytes(block_size, byteorder='big'))
    return unpad_message(b''.join(plaintext_blocks))


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
