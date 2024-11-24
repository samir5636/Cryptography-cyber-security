import random
import base64
import hashlib
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta






def euclide(a, b):
    """Algorithme d'Euclide pour trouver le PGCD"""
    while b != 0:
        a, b = b, a % b
    return a

def euclide_etendu(a, b):
    """Algorithme d'Euclide étendu pour trouver les coefficients de Bézout"""
    if b == 0:
        return a, 1, 0
    else:
        pgcd, u, v = euclide_etendu(b, a % b)
        return pgcd, v, u - (a // b) * v

def generer_e(phi_n):
    """Génère un exposant e cryptographiquement sûr"""
    # On choisit e > 65537 pour plus de sécurité
    e = 65537
    while euclide(e, phi_n) != 1:
        e = random.randrange(65537, phi_n, 2)
    return e

def exp_rapide(base, exposant, modulo):
    """Exponentiation modulaire rapide"""
    resultat = 1
    base = base % modulo
    while exposant > 0:
        if exposant % 2 == 1:
            resultat = (resultat * base) % modulo
        base = (base * base) % modulo
        exposant = exposant >> 1
    return resultat

def generer_cles(p, q):
    """Génère les clés publique et privée"""
    n = p * q
    phi_n = (p - 1) * (q - 1)

    # Génération de e
    e = generer_e(phi_n)

    # Calcul de d (inverse modulaire de e modulo phi_n)
    pgcd, d, _ = euclide_etendu(e, phi_n)
    d = d % phi_n
    if d < 0:
        d += phi_n

    return (e, n), (d, n)

def chiffrer_message(message, cle_publique):
    """Chiffre un message en utilisant la clé publique"""
    e, n = cle_publique
    # Conversion en ASCII et chiffrement
    blocks = []
    for char in message:
        m = ord(char)
        if m >= n:
            raise ValueError("Caractère trop grand pour être chiffré avec ce module")
        c = exp_rapide(m, e, n)
        blocks.append(str(c))

    # Joindre les blocs et encoder en base64
    chiffre = ",".join(blocks)
    return base64.b64encode(chiffre.encode()).decode()

def dechiffrer_message(chiffre_base64, cle_privee):
    """Déchiffre un message en utilisant la clé privée"""
    d, n = cle_privee
    # Décoder le base64 et séparer les blocs
    chiffre = base64.b64decode(chiffre_base64).decode()
    blocks = [int(x) for x in chiffre.split(",")]

    # Déchiffrement et conversion en caractères
    message = ""
    for c in blocks:
        m = exp_rapide(c, d, n)
        message += chr(m)

    return message



# ... (Garder toutes les fonctions précédentes)

def sauvegarder_certificat(private_key, certificate, fichier_cert="certificat.pem", fichier_key="cle_privee.pem"):
    """Sauvegarde le certificat et la clé privée dans des fichiers PEM"""
    # Sauvegarder le certificat
    with open(fichier_cert, "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

    # Sauvegarder la clé privée
    with open(fichier_key, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
        
def generer_certificat():
    """Génère un certificat auto-signé avec OpenSSL"""
    # Générer une paire de clés RSA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Créer le certificat
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"RSA Demo Certificate"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Demo Organization"),
    ]))
    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u"RSA Demo Certificate"),
    ]))
    builder = builder.not_valid_before(datetime.utcnow())
    builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    )

    # Signer le certificat
    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    return private_key, certificate

        
        
 
def generer_signature(message, cle_privee):
    """Génère une signature numérique pour un message"""
    d, n = cle_privee
    # Calculer le hash du message
    hash_obj = hashlib.sha256(message.encode())
    hash_message = hash_obj.digest()
    # Convertir le hash en nombre pour le traitement RSA
    hash_int = int.from_bytes(hash_message[:8], byteorder='big') % n
    # Signer le hash avec la clé privée
    signature = exp_rapide(hash_int, d, n)
    return base64.b64encode(str(signature).encode()).decode()

def verifier_signature(message, signature_base64, cle_publique):
    """Vérifie une signature numérique"""
    e, n = cle_publique
    try:
        # Décoder la signature
        signature = int(base64.b64decode(signature_base64).decode())
        
        # Calculer le hash du message original
        hash_obj = hashlib.sha256(message.encode())
        hash_message = hash_obj.digest()
        hash_int = int.from_bytes(hash_message[:8], byteorder='big') % n
        
        # Vérifier la signature en utilisant la clé publique
        hash_dechiffre = exp_rapide(signature, e, n)
        
        return hash_dechiffre == hash_int
    except Exception as e:
        print(f"Erreur lors de la vérification: {str(e)}")
        return False

def main():
    # Paramètres initiaux
    p = 257
    q = 263
    message = "votre_nom votre_prénom"
    
    # Génération des clés RSA
    cle_publique, cle_privee = generer_cles(p, q)
    print(f"Clé publique (e, n): {cle_publique}")
    print(f"Clé privée (d, n): {cle_privee}")
    
    # Test du chiffrement/déchiffrement
    try:
        # Chiffrement
        chiffre = chiffrer_message(message, cle_publique)
        print(f"\nMessage chiffré (Base64): {chiffre}")
        
        # Déchiffrement
        dechiffre = dechiffrer_message(chiffre, cle_privee)
        print(f"Message déchiffré: {dechiffre}")
        
        # Test de la signature
        print("\nTest de la signature numérique:")
        signature = generer_signature(message, cle_privee)
        print(f"Signature générée: {signature}")
        
        # Vérification immédiate de la signature
        verification = verifier_signature(message, signature, cle_publique)
        print(f"Vérification de la signature: {'Valide' if verification else 'Invalide'}")
        
        # Test avec un message modifié
        message_modifie = message + "x"
        verification_message_modifie = verifier_signature(message_modifie, signature, cle_publique)
        print(f"Vérification avec message modifié: {'Valide' if verification_message_modifie else 'Invalide'}")
        
    except Exception as e:
        print(f"Erreur lors du traitement: {str(e)}")
    
    # Génération et sauvegarde du certificat
    try:
        print("\nGénération du certificat...")
        private_key, certificate = generer_certificat()
        sauvegarder_certificat(private_key, certificate)
        print("Certificat et clé privée générés et sauvegardés avec succès!")
        print("- Certificat: certificat.pem")
        print("- Clé privée: cle_privee.pem")
    except Exception as e:
        print(f"Erreur lors de la génération du certificat: {str(e)}")

if __name__ == "__main__":
    main()