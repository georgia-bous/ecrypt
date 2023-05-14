import math
import random
import sympy
import os


# Function to generate a prime number
def generate_prime():
    # Generate a random number with 1024 bits.
    p = random.getrandbits(1024)
    if is_prime(p):
        return p
    else:
        t = sympy.nextprime(p)
        return t


# Function to check if number is prime with Miller-Rabin primality test.
def is_prime(n, k=128):
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
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
    padded_msg = msg + padding
    return padded_msg


# Function to unpad the message
def unpad_message(padded_message):
    padding_length = padded_message[-1]
    return padded_message[:-padding_length]


# Function that performs encryption with ECB mode
def encrypt_ecb(public_key, msg):
    # Extracts public key values
    n, e = public_key
    # Calculates the block size needed based on the key length
    block_size = (n.bit_length() + 7) // 8 - 1
    # Pads the message to be a multiple of the block size
    padded_msg = pad_message(msg.encode(), block_size)
    # Breaks the padded message into blocks
    blocks = [padded_msg[i:i + block_size] for i in range(0, len(padded_msg), block_size)]
    cipher_blocks = []
    # Encrypts each block and appends it to a list
    for block in blocks:
        m = int.from_bytes(block, byteorder='big')
        c = pow(m, e, n)
        cipher_blocks.append(c.to_bytes(block_size + 1, byteorder='big'))
    # Joins the encrypted blocks into a single byte string
    return b''.join(cipher_blocks)


# Function that performs decryption with ECB mode
def decrypt_ecb(private_key, ciphertext):
    # Extracts private key values
    n, d = private_key
    # Calculates the block size needed based on the key length
    block_size = (n.bit_length() + 7) // 8 - 1
    # Breaks the ciphertext into blocks
    blocks = [ciphertext[i:i + block_size + 1] for i in range(0, len(ciphertext), block_size + 1)]
    # Decrypts each block and appends it to a list
    plaintext_blocks = []
    for block in blocks:
        c = int.from_bytes(block, byteorder='big')
        m = pow(c, d, n)
        plaintext_blocks.append(m.to_bytes(block_size, byteorder='big'))
    # Joins the decrypted blocks into a single byte string
    plaintext = unpad_message(b''.join(plaintext_blocks))
    # Removes any leading null bytes and returns the plaintext as a string
    plaintext = plaintext.lstrip(b'\x00')
    return plaintext.decode('utf-8')


# Function that performs encryption with CBC mode
def encrypt_cbc(public_key, msg):
    # Extracts public key values
    n, e = public_key
    # Calculates the block size needed based on the key length
    block_size = (n.bit_length() + 7) // 8 - 1
    # Generates a random initialization vector
    iv = os.urandom(block_size)
    # Pads the message to be a multiple of the block size
    padded_msg = pad_message(msg.encode(), block_size)
    # Breaks the padded message into blocks and XORs each block with the previous ciphertext block
    blocks = [padded_msg[i:i + block_size] for i in range(0, len(padded_msg), block_size)]
    cipher_blocks = [iv]
    for block in blocks:
        m = int.from_bytes(block, byteorder='big')
        c = pow(m ^ int.from_bytes(cipher_blocks[-1], byteorder='big'), e, n)
        cipher_blocks.append(c.to_bytes(block_size + 1, byteorder='big'))
    # Joins the initialization vector and the encrypted blocks into a single byte string
    ciphertext = iv + b''.join(cipher_blocks[1:])
    return ciphertext


# Function that performs decryption with CBC mode
def decrypt_cbc(private_key, ciphertext):
    # Extracts private key values
    n, d = private_key
    # Calculates the block size needed based on the key length
    block_size = (n.bit_length() + 7) // 8 - 1
    iv = ciphertext[:block_size]
    # Breaks the ciphertext into blocks
    blocks = [ciphertext[i:i + block_size + 1] for i in range(block_size, len(ciphertext), block_size + 1)]
    # Decrypts each block and appends it to a list
    plaintext_blocks = []
    prev_block = iv
    for block in blocks:
        c = int.from_bytes(block, byteorder='big')
        m = pow(c, d, n) ^ int.from_bytes(prev_block, byteorder='big')
        plaintext_blocks.append(m.to_bytes(block_size, byteorder='big'))
        prev_block = block
    # Joins the decrypted blocks into a single byte string
    plaintext = unpad_message(b''.join(plaintext_blocks))
    # Removes any leading null bytes and returns the plaintext as a string
    plaintext = plaintext.lstrip(b'\x00')
    return plaintext.decode()


# Generate random public and private key
public_key, private_key = generate_keys()

# Give a text file as an input
filename = input("Enter the filename containing the message: ")
try:
    with open(filename, 'r') as f:
        msg = f.read()
except FileNotFoundError:
    print("Error: File not found")
    exit()

# Print the outcome of the ECB mode
print("ECB: ")
c1 = encrypt_ecb(public_key, msg)
print("Ciphertext: ", c1)
dm1 = decrypt_ecb(private_key, c1)

# Print the decrypted message
print("Decrypted message:", dm1)

# Print the outcome of the ECB mode
print("CBC: ")
c2 = encrypt_cbc(public_key, msg)
print("Ciphertext: ", c2)
dm2 = decrypt_cbc(private_key, c2)

# Print the decrypted message
print("Decrypted message:", dm2)
