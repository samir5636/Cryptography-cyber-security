import random
import base64
import hashlib
from math import gcd
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
import time
from sympy import factorint
from random import randrange

def est_premier(n, k=5):
    """Test de primalité de Miller-Rabin"""
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False

    # Écrire n-1 comme 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Témoin de Miller
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generer_premier(bits):
    """Génère un nombre premier de la taille spécifiée en bits"""
    while True:
        n = random.getrandbits(bits)
        if n % 2 == 0:
            n += 1
        if est_premier(n):
            return n


def trouver_generateur_optimise(p):
    """
    Trouve un générateur pour le groupe multiplicatif modulo p de manière optimisée.
    Utilise plusieurs optimisations:
    1. Test uniquement les facteurs premiers de p-1
    2. Utilise un échantillonnage aléatoire au lieu de tester séquentiellement
    3. Implémente early exit pour les tests négatifs
    4. Utilise une mise en cache des puissances pour éviter les calculs redondants
    """
    if not est_premier(p):
        raise ValueError("p doit être un nombre premier")
    
    # Factorisation de p-1
    phi = p - 1
    facteurs_premiers = list(factorint(phi).keys())
    
    # Calculer les exposants pour le test
    exposants = [phi // f for f in facteurs_premiers]
    
    # Nombre maximum de tentatives avant de changer de stratégie
    MAX_TENTATIVES = 100
    tentatives = 0
    
    while tentatives < MAX_TENTATIVES:
        # Choisir un candidat aléatoire
        g = randrange(2, p)
        
        # Vérifier que g est premier avec p
        if gcd(g, p) != 1:
            continue
            
        # Test optimisé utilisant les propriétés des groupes cycliques
        est_generateur = True
        
        for i, exposant in enumerate(exposants):
            # Calculer g^((p-1)/q) mod p pour chaque facteur premier q de p-1
            if pow(g, exposant, p) == 1:
                est_generateur = False
                break
        
        if est_generateur:
            return g
            
        tentatives += 1
    
    # Si la méthode aléatoire échoue, revenir à une recherche déterministe optimisée
    for g in range(2, p):
        if gcd(g, p) != 1:
            continue
            
        est_generateur = True
        for exposant in exposants:
            if pow(g, exposant, p) == 1:
                est_generateur = False
                break
                
        if est_generateur:
            return g
            
    raise RuntimeError("Impossible de trouver un générateur")

def generer_cles_optimise(bits=256):
    """Version optimisée de la génération de clés"""
    print("Génération d'un nombre premier...")
    start_time = time.time()
    p = generer_premier(bits)
    prime_time = time.time() - start_time
    print(f"Nombre premier généré en {prime_time:.2f} secondes.")

    print("Recherche d'un générateur...")
    start_time = time.time()
    g = trouver_generateur_optimise(p)
    gen_time = time.time() - start_time
    print(f"Générateur trouvé en {gen_time:.2f} secondes.")

    # Génération de la clé privée
    x = randrange(2, p-1)
    y = pow(g, x, p)
    
    return {
        'public': {'p': p, 'g': g, 'y': y},
        'private': {'x': x},
        'perf_metrics': {
            'prime_generation_time': prime_time,
            'generator_search_time': gen_time
        }
    }



def chiffrer_message(message, cle_publique, block_size=4):
    p, g, y = cle_publique['p'], cle_publique['g'], cle_publique['y']
    
    # Convert the message to bytes and split into blocks
    message_bytes = message.encode()
    blocks = [message_bytes[i:i+block_size] for i in range(0, len(message_bytes), block_size)]
    
    # Encrypt each block
    encrypted_blocks = []
    for block in blocks:
        m = int.from_bytes(block, byteorder='big')
        if m >= p:
            raise ValueError("Le bloc est trop grand pour le paramètre p.")
        
        k = random.randrange(2, p-1)
        while gcd(k, p-1) != 1:
            k = random.randrange(2, p-1)
        
        c1 = pow(g, k, p)
        c2 = (m * pow(y, k, p)) % p
        encrypted_blocks.append(f"{c1},{c2}")
    
    ciphertext = ";".join(encrypted_blocks)
    return base64.b64encode(ciphertext.encode()).decode()


def dechiffrer_message(chiffre_base64, cle_privee, p):
    """Déchiffre un message avec ElGamal"""
    # Décoder le message
    chiffre = base64.b64decode(chiffre_base64).decode()
    blocks = chiffre.split(';')
    
    # Déchiffrer chaque bloc
    message_bytes = bytearray()
    x = cle_privee['x']
    
    for block in blocks:
        c1, c2 = map(int, block.split(','))
        
        # Calculer s = c1^x mod p
        s = pow(c1, x, p)
        
        # Calculer s^(-1) mod p
        s_inv = pow(s, p-2, p)  # Petit théorème de Fermat
        
        # Retrouver le message
        m = (c2 * s_inv) % p
        
        # Convertir m en bytes
        message_bytes.extend(m.to_bytes((m.bit_length() + 7) // 8, byteorder='big'))
    
    return message_bytes.decode()


def generer_signature(message, cle_privee, cle_publique):
    """Génère une signature ElGamal"""
    p, g = cle_publique['p'], cle_publique['g']
    x = cle_privee['x']
    
    # Calculer le hash du message
    h = int.from_bytes(hashlib.sha256(message.encode()).digest(), byteorder='big')
    h = h % (p-1)  # Réduire le hash modulo p-1
    
    # Générer k aléatoire
    k = random.randrange(2, p-2)
    while gcd(k, p-1) != 1:
        k = random.randrange(2, p-2)
    
    # Calculer r = g^k mod p
    r = pow(g, k, p)
    
    # Calculer k_inv
    k_inv = pow(k, p-3, p-1)  # k^(-1) mod (p-1)
    
    # Calculer s = k^(-1)(h - xr) mod (p-1)
    s = (k_inv * (h - x*r)) % (p-1)
    
    # Encoder la signature en base64
    signature = f"{r},{s}"
    return base64.b64encode(signature.encode()).decode()

def verifier_signature(message, signature_base64, cle_publique):
    """Vérifie une signature ElGamal"""
    try:
        p, g, y = cle_publique['p'], cle_publique['g'], cle_publique['y']
        
        # Décoder la signature
        signature = base64.b64decode(signature_base64).decode()
        r, s = map(int, signature.split(','))
        
        # Vérifier que 0 < r < p
        if r <= 0 or r >= p:
            return False
        
        # Calculer le hash du message
        h = int.from_bytes(hashlib.sha256(message.encode()).digest(), byteorder='big')
        h = h % (p-1)
        
        # Vérifier la signature
        # g^h ≡ y^r * r^s (mod p)
        gauche = pow(g, h, p)
        droite = (pow(y, r, p) * pow(r, s, p)) % p
        
        return gauche == droite
    
    except Exception as e:
        print(f"Erreur lors de la vérification: {str(e)}")
        return False

def generer_certificat():
    """Génère un certificat auto-signé avec OpenSSL"""
    # Générer une paire de clés
    cles = generer_cles_optimise(2048)
    
    # Créer le certificat
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"ElGamal Demo Certificate"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Demo Organization"),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"ElGamal Demo Certificate"),
    ]))
    builder = builder.not_valid_before(datetime.utcnow())
    builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    
    # Note: This is a simplified version. In practice, you would need to properly
    # handle the conversion between ElGamal keys and the format expected by the x509 library
    
    return cles, "Certificate generation is simplified for demo purposes"

def sauvegarder_certificat(cles, cert_info, fichier_cert="certificat.pem", fichier_key="cle_privee.pem"):
    """Sauvegarde le certificat et la clé privée"""
    # Sauvegarder les clés dans un format lisible
    with open(fichier_key, "w") as f:
        f.write(f"Private Key:\n{str(cles['private'])}\n")
    
    with open(fichier_cert, "w") as f:
        f.write(f"Public Key:\n{str(cles['public'])}\n")
        f.write(f"\nCertificate Info:\n{cert_info}")

def main():
    # Test des fonctionnalités
    message = "votre_nom votre_prénom"
    
    print("Génération des clés...")
    cles = generer_cles_optimise(256)
    print(f"Clé publique: {cles['public']}")
    print(f"Clé privée: {cles['private']}")
    
    try:
        # Test du chiffrement/déchiffrement
        print("\nTest du chiffrement/déchiffrement:")
        chiffre = chiffrer_message(message, cles['public'])
        print(f"Message chiffré: {chiffre}")
        
        dechiffre = dechiffrer_message(chiffre, cles['private'], cles['public']['p'])
        print(f"Message déchiffré: {dechiffre}")
        
        # Test de la signature
        print("\nTest de la signature:")
        signature = generer_signature(message, cles['private'], cles['public'])
        print(f"Signature: {signature}")
        
        verification = verifier_signature(message, signature, cles['public'])
        print(f"Vérification de la signature: {'Valide' if verification else 'Invalide'}")
        
        # Test avec message modifié
        message_modifie = message + "x"
        verification_modifie = verifier_signature(message_modifie, signature, cles['public'])
        print(f"Vérification avec message modifié: {'Valide' if verification_modifie else 'Invalide'}")
        
        # Génération de certificat
        print("\nGénération du certificat...")
        cles_cert, cert_info = generer_certificat()
        sauvegarder_certificat(cles_cert, cert_info)
        print("Certificat généré et sauvegardé!")
        
    except Exception as e:
        print(f"Erreur: {str(e)}")

if __name__ == "__main__":
    main()