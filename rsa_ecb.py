import math
import random
import sympy
import sys


def gcd(a, b):
    while b != 0:
        r = a % b
        a = b
        b = r
    return a
    
def generate_prime(): #uses miller rabin, not 100%
    # Generate a random number with 512 bits.
    t = random.getrandbits(512)  #would be good to assure its big
    p = sympy.nextprime(t)
    return p


def modinv(a, m):
    # Compute the modular inverse of a modulo m using the extended Euclidean algorithm
    # https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Computing_multiplicative_inverses_in_modular_structures
    x, y, lastx, lasty = 0, 1, 1, 0
    while m:
        a, (q, m) = m, divmod(a, m)
        lastx, x = x, lastx - q * x
        lasty, y = y, lasty - q * y
    return lastx

def encrypt(n, e, m):
    c = [pow(int(ord(char)), e, n) for char in m]
    return c

def decrypt(n, d, c):
    dm = [chr(pow(char, d, n)) for char in c]
    return ''.join(dm)


p=generate_prime()
q=generate_prime() #would be better if p!=q
n=p*q
phi=(p-1)*(q-1)
e=random.randint(2, phi-1)

while(gcd(e, phi)!=1):
    e=random.randint(2, phi-1)

d = modinv(e, phi)
    
msg=input('Enter the message you want to send: ')
c=encrypt(n, e, msg)
print('Ciphertext: ', c)
dm=decrypt(n, d, c)
print('Decrypted message: ', dm)
