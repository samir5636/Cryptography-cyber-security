from dash import html, dcc
import base64
from typing import Tuple
from dash import callback
from dash.dependencies import Input, Output, State
import json


# ElGamal Callbacks
@callback(
    [Output('params-output-elgamal', 'children'),
     Output('params-store-elgamal', 'data')],
    [Input('generate-params-elgamal', 'n_clicks')]
)
def generate_parameters(n_clicks):
    if n_clicks == 0:
        return "", None
    try:
        p, g = generate_prime_and_generator()
        params = {'p': p, 'g': g}
        return (
            [
                html.Div(f"Prime (p): {p}"),
                html.Div(f"Generator (g): {g}")
            ],
            json.dumps(params)
        )
    except Exception as e:
        return f"Error: {str(e)}", None

@callback(
    [Output('key-output-elgamal', 'children'),
     Output('public-key-store-elgamal', 'data'),
     Output('private-key-store-elgamal', 'data')],
    [Input('generate-keys-elgamal', 'n_clicks')],
    [State('params-store-elgamal', 'data')]
)
def generate_key_pair(n_clicks, params_json):
    if n_clicks == 0 or not params_json:
        return "", None, None
    try:
        params = json.loads(params_json)
        p, g = params['p'], params['g']
        public_key, private_key = generate_keys(p, g)
        return (
            [
                html.Div(f"Public Key (p, g, y): {public_key}"),
                html.Div(f"Private Key (x): {private_key}")
            ],
            json.dumps(public_key),
            json.dumps(private_key)
        )
    except Exception as e:
        return f"Error: {str(e)}", None, None

@callback(
    Output('encryption-output-elgamal', 'children'),
    [Input('encrypt-button-elgamal', 'n_clicks')],
    [State('input-message-elgamal', 'value'),
     State('public-key-store-elgamal', 'data')]
)
def encrypt_message_callback(n_clicks, message, public_key_json):
    if n_clicks == 0 or not message or not public_key_json:
        return ""
    try:
        public_key = tuple(json.loads(public_key_json))
        encrypted = encrypt(message, public_key)
        return f"Encrypted message: {encrypted}"
    except Exception as e:
        return f"Error: {str(e)}"

@callback(
    Output('decryption-output-elgamal', 'children'),
    [Input('decrypt-button-elgamal', 'n_clicks')],
    [State('input-cipher-elgamal', 'value'),
     State('private-key-store-elgamal', 'data'),
     State('params-store-elgamal', 'data')]
)
def decrypt_message_callback(n_clicks, cipher, private_key_json, params_json):
    if n_clicks == 0 or not cipher or not private_key_json or not params_json:
        return ""
    try:
        params = json.loads(params_json)
        private_key = json.loads(private_key_json)
        decrypted = decrypt(cipher, private_key, params['p'])
        return f"Decrypted message: {decrypted}"
    except Exception as e:
        return f"Error: {str(e)}"

@callback(
    [Output('signature-output-elgamal', 'children'),
     Output('signature-store-elgamal', 'data')],
    [Input('sign-button-elgamal', 'n_clicks')],
    [State('signature-message-elgamal', 'value'),
     State('private-key-store-elgamal', 'data'),
     State('params-store-elgamal', 'data')]
)
def sign_message_callback(n_clicks, message, private_key_json, params_json):
    if n_clicks == 0 or not message or not private_key_json or not params_json:
        return "", None
    try:
        params = json.loads(params_json)
        private_key = json.loads(private_key_json)
        signature = generate_signature(message, private_key, params['p'], params['g'])
        return f"Signature: {signature}", signature
    except Exception as e:
        return f"Error: {str(e)}", None

@callback(
    Output('verification-output-elgamal', 'children'),
    [Input('verify-button-elgamal', 'n_clicks')],
    [State('signature-message-elgamal', 'value'),
     State('signature-store-elgamal', 'data'),
     State('public-key-store-elgamal', 'data')]
)
def verify_message_callback(n_clicks, message, signature, public_key_json):
    if n_clicks == 0 or not message or not signature or not public_key_json:
        return ""
    try:
        public_key = tuple(json.loads(public_key_json))
        is_valid = verify_signature(message, signature, public_key)
        return html.Div(
            "Signature is valid" if is_valid else "Signature is invalid",
            style={"color": "#00FF00" if is_valid else "#FF0000"}
        )
    except Exception as e:
        return f"Error: {str(e)}"

def generate_prime_and_generator(bits: int = 8) -> Tuple[int, int]:
    """Generate a prime number p and a generator g for the multiplicative group Z*p"""
    # For demo purposes, using small numbers. In practice, use larger primes
    p = 2357  # Using a fixed prime for demonstration
    g = 2
    return p, g

def generate_keys(p: int, g: int) -> Tuple[Tuple[int, int, int], int]:
    """Generate public and private keys"""
    import random
    # Private key
    x = random.randint(2, p-2)
    # Public key component
    y = pow(g, x, p)
    return ((p, g, y), x)

def encrypt(message: str, public_key: Tuple[int, int, int]) -> str:
    """Encrypt a message using El Gamal encryption"""
    import random
    p, g, y = public_key
    encrypted_blocks = []
    
    for m in [ord(c) for c in message]:
        k = random.randint(2, p-2)
        c1 = pow(g, k, p)
        c2 = (m * pow(y, k, p)) % p
        encrypted_blocks.append(f"{c1},{c2}")
    
    encrypted_data = ";".join(encrypted_blocks)
    return base64.b64encode(encrypted_data.encode()).decode()

def decrypt(encrypted_data: str, private_key: int, p: int) -> str:
    """Decrypt a message using El Gamal private key"""
    encrypted_blocks = base64.b64decode(encrypted_data.encode()).decode().split(";")
    decrypted_message = ""
    
    for block in encrypted_blocks:
        c1, c2 = map(int, block.split(","))
        s = pow(c1, private_key, p)
        s_inverse = pow(s, p-2, p)
        m = (c2 * s_inverse) % p
        decrypted_message += chr(m)
    
    return decrypted_message

def generate_signature(message: str, private_key: int, p: int, g: int) -> str:
    """Generate El Gamal signature for a message"""
    import random
    import hashlib
    from math import gcd
    
    hash_obj = hashlib.sha256(message.encode())
    hash_int = int.from_bytes(hash_obj.digest(), byteorder='big') % (p-1)
    
    k = random.randint(2, p-2)
    while gcd(k, p-1) != 1:
        k = random.randint(2, p-2)
    
    r = pow(g, k, p)
    k_inverse = pow(k, p-3, p-1)
    s = (k_inverse * (hash_int - private_key * r)) % (p-1)
    
    signature = f"{r},{s}"
    return base64.b64encode(signature.encode()).decode()

def verify_signature(message: str, signature: str, public_key: Tuple[int, int, int]) -> bool:
    """Verify El Gamal signature"""
    import hashlib
    
    p, g, y = public_key
    
    try:
        r, s = map(int, base64.b64decode(signature.encode()).decode().split(","))
        
        if r <= 0 or r >= p:
            return False
        
        hash_obj = hashlib.sha256(message.encode())
        hash_int = int.from_bytes(hash_obj.digest(), byteorder='big') % (p-1)
        
        left_side = pow(g, hash_int, p)
        right_side = (pow(y, r, p) * pow(r, s, p)) % p
        
        return left_side == right_side
    
    except Exception as e:
        print(f"Error during signature verification: {str(e)}")
        return False

def create_elgamal_layout():
    """Create the El Gamal dashboard layout"""
    return html.Div(
        style={
            "backgroundColor": "#000",
            "color": "#00FF00",
            "fontFamily": "Courier New, monospace",
            "minHeight": "100vh",
            "padding": "20px",
        },
        children=[
            # Header is now in main app.py
            
            # System Parameters Section
            html.Div(
                style={
                    "backgroundColor": "#0D0D0D",
                    "padding": "20px",
                    "margin": "20px 0",
                    "border": "2px solid #00FF00",
                },
                children=[
                    html.H3("System Parameters", style={"color": "#00FF00"}),
                    html.Button(
                        "Generate Parameters",
                        id="generate-params-elgamal",
                        n_clicks=0,
                        style={
                            "backgroundColor": "#00FF00",
                            "color": "black",
                            "padding": "10px",
                            "marginTop": "10px",
                            "cursor": "pointer",
                        }
                    ),
                    html.Div(id="params-output-elgamal", style={"marginTop": "10px"})
                ]
            ),
            
            # Key Generation Section
            html.Div(
                style={
                    "backgroundColor": "#0D0D0D",
                    "padding": "20px",
                    "margin": "20px 0",
                    "border": "2px solid #00FF00",
                },
                children=[
                    html.H3("Key Generation", style={"color": "#00FF00"}),
                    html.Button(
                        "Generate Keys",
                        id="generate-keys-elgamal",
                        n_clicks=0,
                        style={
                            "backgroundColor": "#00FF00",
                            "color": "black",
                            "padding": "10px",
                            "marginTop": "10px",
                            "cursor": "pointer",
                        }
                    ),
                    html.Div(id="key-output-elgamal", style={"marginTop": "10px"})
                ]
            ),
            
            # Encryption/Decryption Section
            html.Div(
                style={
                    "display": "flex",
                    "gap": "20px",
                    "margin": "20px 0",
                },
                children=[
                    # Encryption Box
                    html.Div(
                        style={
                            "flex": 1,
                            "backgroundColor": "#0D0D0D",
                            "padding": "20px",
                            "border": "2px solid #00FF00",
                        },
                        children=[
                            html.H3("Encryption", style={"color": "#00FF00"}),
                            dcc.Textarea(
                                id="input-message-elgamal",
                                placeholder="Enter message to encrypt...",
                                style={
                                    "width": "100%",
                                    "height": "100px",
                                    "backgroundColor": "#1a1a1a",
                                    "color": "#00FF00",
                                    "border": "1px solid #00FF00",
                                }
                            ),
                            html.Button(
                                "Encrypt",
                                id="encrypt-button-elgamal",
                                n_clicks=0,
                                style={
                                    "backgroundColor": "#00FF00",
                                    "color": "black",
                                    "padding": "10px",
                                    "marginTop": "10px",
                                    "width": "100%",
                                    "cursor": "pointer",
                                }
                            ),
                            html.Div(id="encryption-output-elgamal", style={"marginTop": "10px", "wordBreak": "break-all"})
                        ]
                    ),
                    
                    # Decryption Box
                    html.Div(
                        style={
                            "flex": 1,
                            "backgroundColor": "#0D0D0D",
                            "padding": "20px",
                            "border": "2px solid #00FF00",
                        },
                        children=[
                            html.H3("Decryption", style={"color": "#00FF00"}),
                            dcc.Textarea(
                                id="input-cipher-elgamal",
                                placeholder="Enter message to decrypt...",
                                style={
                                    "width": "100%",
                                    "height": "100px",
                                    "backgroundColor": "#1a1a1a",
                                    "color": "#00FF00",
                                    "border": "1px solid #00FF00",
                                }
                            ),
                            html.Button(
                                "Decrypt",
                                id="decrypt-button-elgamal",
                                n_clicks=0,
                                style={
                                    "backgroundColor": "#00FF00",
                                    "color": "black",
                                    "padding": "10px",
                                    "marginTop": "10px",
                                    "width": "100%",
                                    "cursor": "pointer",
                                }
                            ),
                            html.Div(id="decryption-output-elgamal", style={"marginTop": "10px", "wordBreak": "break-all"})
                        ]
                    )
                ]
            ),
            
            # Digital Signature Section
            html.Div(
                style={
                    "backgroundColor": "#0D0D0D",
                    "padding": "20px",
                    "margin": "20px 0",
                    "border": "2px solid #00FF00",
                },
                children=[
                    html.H3("Digital Signature", style={"color": "#00FF00"}),
                    dcc.Textarea(
                        id="signature-message-elgamal",
                        placeholder="Enter message to sign...",
                        style={
                            "width": "100%",
                            "height": "100px",
                            "backgroundColor": "#1a1a1a",
                            "color": "#00FF00",
                            "border": "1px solid #00FF00",
                        }
                    ),
                    html.Button(
                        "Sign Message",
                        id="sign-button-elgamal",
                        n_clicks=0,
                        style={
                            "backgroundColor": "#00FF00",
                            "color": "black",
                            "padding": "10px",
                            "marginTop": "10px",
                            "width": "100%",
                            "cursor": "pointer",
                        }
                    ),
                    html.Div(id="signature-output-elgamal", style={"marginTop": "10px", "wordBreak": "break-all"}),
                    html.Button(
                        "Verify Signature",
                        id="verify-button-elgamal",
                        n_clicks=0,
                        style={
                            "backgroundColor": "#00FF00",
                            "color": "black",
                            "padding": "10px",
                            "marginTop": "10px",
                            "width": "100%",
                            "cursor": "pointer",
                        }
                    ),
                    html.Div(id="verification-output-elgamal", style={"marginTop": "10px"})
                ]
            ),
            
            # Store components for maintaining state
            dcc.Store(id='params-store-elgamal'),
            dcc.Store(id='public-key-store-elgamal'),
            dcc.Store(id='private-key-store-elgamal'),
            dcc.Store(id='signature-store-elgamal'),
        ]
    )