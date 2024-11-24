import random
import base64
import hashlib
from math import gcd
from typing import Tuple, List

def generate_prime_and_generator(bits: int = 8) -> Tuple[int, int]:
    """
    Generate a prime number p and a generator g for the multiplicative group Z*p
    """
    # For demo purposes, using small numbers. In practice, use larger primes
    p = 2357  # Using a fixed prime for demonstration
    
    # Find a generator
    def is_generator(g: int, p: int) -> bool:
        # Check if g is a generator of Z*p
        factors = {2, (p-1)//2}  # Prime factors of p-1
        for factor in factors:
            if pow(g, (p-1)//factor, p) == 1:
                return False
        return True
    
    g = 2
    while not is_generator(g, p):
        g += 1
    
    return p, g

def generate_keys(p: int, g: int) -> Tuple[Tuple[int, int, int], int]:
    """
    Generate public and private keys
    Returns: ((p, g, y), x) where (p, g, y) is public key and x is private key
    """
    # Private key
    x = random.randint(2, p-2)
    
    # Public key component
    y = pow(g, x, p)
    
    return ((p, g, y), x)

def encode_message(message: str) -> List[int]:
    """Convert string message to list of integers"""
    return [ord(c) for c in message]

def decode_message(numbers: List[int]) -> str:
    """Convert list of integers back to string"""
    return ''.join(chr(n) for n in numbers)

def encrypt(message: str, public_key: Tuple[int, int, int]) -> str:
    """
    Encrypt a message using El Gamal encryption
    Returns base64 encoded string of encrypted data
    """
    p, g, y = public_key
    encoded_msg = encode_message(message)
    encrypted_blocks = []
    
    for m in encoded_msg:
        # Generate ephemeral key
        k = random.randint(2, p-2)
        while gcd(k, p-1) != 1:
            k = random.randint(2, p-2)
        
        # Calculate c1 = g^k mod p
        c1 = pow(g, k, p)
        
        # Calculate c2 = m * y^k mod p
        c2 = (m * pow(y, k, p)) % p
        
        encrypted_blocks.append(f"{c1},{c2}")
    
    # Join blocks and encode in base64
    encrypted_data = ";".join(encrypted_blocks)
    return base64.b64encode(encrypted_data.encode()).decode()

def decrypt(encrypted_data: str, private_key: int, p: int) -> str:
    """
    Decrypt a message using El Gamal private key
    Expects base64 encoded string of encrypted data
    """
    # Decode base64 and split into blocks
    encrypted_blocks = base64.b64decode(encrypted_data.encode()).decode().split(";")
    decrypted_numbers = []
    
    for block in encrypted_blocks:
        c1, c2 = map(int, block.split(","))
        
        # Calculate s = c1^x mod p
        s = pow(c1, private_key, p)
        
        # Calculate s_inverse = s^(-1) mod p
        s_inverse = pow(s, p-2, p)  # Using Fermat's little theorem
        
        # Recover message m = c2 * s_inverse mod p
        m = (c2 * s_inverse) % p
        decrypted_numbers.append(m)
    
    return decode_message(decrypted_numbers)

def generate_signature(message: str, private_key: int, p: int, g: int) -> str:
    """Generate El Gamal signature for a message"""
    # Hash the message
    hash_obj = hashlib.sha256(message.encode())
    hash_int = int.from_bytes(hash_obj.digest(), byteorder='big') % (p-1)
    
    # Generate k (ephemeral key)
    k = random.randint(2, p-2)
    while gcd(k, p-1) != 1:
        k = random.randint(2, p-2)
    
    # Calculate r = g^k mod p
    r = pow(g, k, p)
    
    # Calculate k_inverse
    k_inverse = pow(k, p-3, p-1)  # Using Fermat's little theorem since p-1 is even
    
    # Calculate s = k_inverse * (hash - x*r) mod (p-1)
    s = (k_inverse * (hash_int - private_key * r)) % (p-1)
    
    # Encode signature
    signature = f"{r},{s}"
    return base64.b64encode(signature.encode()).decode()

def verify_signature(message: str, signature: str, public_key: Tuple[int, int, int]) -> bool:
    """Verify El Gamal signature"""
    p, g, y = public_key
    
    try:
        # Decode signature
        r, s = map(int, base64.b64decode(signature.encode()).decode().split(","))
        
        # Check if r is in range
        if r <= 0 or r >= p:
            return False
        
        # Hash the message
        hash_obj = hashlib.sha256(message.encode())
        hash_int = int.from_bytes(hash_obj.digest(), byteorder='big') % (p-1)
        
        # Verify signature
        left_side = pow(g, hash_int, p)
        right_side = (pow(y, r, p) * pow(r, s, p)) % p
        
        return left_side == right_side
    
    except Exception as e:
        print(f"Error during signature verification: {str(e)}")
        return False

def main():
    # Generate system parameters
    p, g = generate_prime_and_generator()
    print(f"System parameters:\np = {p}\ng = {g}")
    
    # Generate keys
    public_key, private_key = generate_keys(p, g)
    print(f"\nPublic key (p, g, y): {public_key}")
    print(f"Private key (x): {private_key}")
    
    # Test message
    message = "votre_nom votre_prénom"
    print(f"\nOriginal message: {message}")
    
    try:
        # Encryption test
        encrypted = encrypt(message, public_key)
        print(f"Encrypted (Base64): {encrypted}")
        
        # Decryption test
        decrypted = decrypt(encrypted, private_key, p)
        print(f"Decrypted: {decrypted}")
        
        # Signature test
        print("\nTesting digital signature:")
        signature = generate_signature(message, private_key, p, g)
        print(f"Generated signature: {signature}")
        
        # Verify signature
        verification = verify_signature(message, signature, public_key)
        print(f"Signature verification: {'Valid' if verification else 'Invalid'}")
        
        # Test with modified message
        modified_message = message + "x"
        verification_modified = verify_signature(modified_message, signature, public_key)
        print(f"Verification with modified message: {'Valid' if verification_modified else 'Invalid'}")
        
    except Exception as e:
        print(f"Error during processing: {str(e)}")

if __name__ == "__main__":
    main()