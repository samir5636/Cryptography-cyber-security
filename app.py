import base64
import random
from math import gcd

# Étape 1: Génération des clés RSA
def generate_keys(p, q):
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Générer un e cryptographiquement sûr
    e = generate_random_e(phi_n)
    
    # Calcul de d avec l'algorithme d'Euclide étendu
    d = extended_euclidean(e, phi_n)[1]
    if d < 0:
        d += phi_n
    
    return (e, n), (d, n)

# Algorithme d'Euclide
def euclidean(a, b):
    while b != 0:
        a, b = b, a % b
    return a

# Algorithme d'Euclide étendu
def extended_euclidean(a, b):
    if b == 0:
        return a, 1, 0
    gcd, x1, y1 = extended_euclidean(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return gcd, x, y

# Exponentiation rapide
def fast_exp(base, exp, mod):
    result = 1
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result

# Générer un e aléatoire
def generate_random_e(phi_n, min_value=3):
    while True:
        e = random.randint(min_value, phi_n - 1)
        if gcd(e, phi_n) == 1:
            return e

# Chiffrement d'un message
def encrypt_message(message, public_key):
    e, n = public_key
    # Conversion ASCII
    ascii_values = [ord(char) for char in message]
    # Chiffrement des blocs
    encrypted_blocks = [fast_exp(val, e, n) for val in ascii_values]
    # Conversion en Base64
    encrypted_bytes = ",".join(map(str, encrypted_blocks)).encode()
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode()
    return encrypted_base64

# Déchiffrement d'un message
def decrypt_message(encrypted_base64, private_key):
    d, n = private_key
    # Décodage Base64
    encrypted_bytes = base64.b64decode(encrypted_base64).decode()
    encrypted_blocks = list(map(int, encrypted_bytes.split(",")))
    # Déchiffrement des blocs
    decrypted_ascii = [fast_exp(block, d, n) for block in encrypted_blocks]
    # Conversion en texte
    decrypted_message = "".join(chr(val) for val in decrypted_ascii)
    return decrypted_message

# Étape 2: Données initiales
p = 257
q = 263
message = "ziani\nsamir\n"

# Génération des clés
public_key, private_key = generate_keys(p, q)

# Affichage des clés
print("Clé publique :", public_key)
print("Clé privée :", private_key)

# Chiffrement
encrypted_message = encrypt_message(message, public_key)
print("Message chiffré (Base64) :", encrypted_message)

# Déchiffrement
decrypted_message = decrypt_message(encrypted_message, private_key)
print("Message déchiffré :", decrypted_message)
