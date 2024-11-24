from dash import html, dcc, callback, Input, Output, State
from RSA import (
    generer_cles, chiffrer_message, dechiffrer_message,
    generer_signature, verifier_signature, generer_certificat,
    sauvegarder_certificat
)

def create_rsa_layout():
    """Create the RSA dashboard layout with namespaced component IDs"""
    return html.Div(
        style={
            "backgroundColor": "#000",
            "color": "#00FF00",
            "fontFamily": "Courier New, monospace",
            "minHeight": "100vh",
            "padding": "20px",
        },
        children=[
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
                    html.Div([
                        html.Label("Prime p:", style={"marginRight": "10px"}),
                        dcc.Input(id="rsa-input-p", type="number", value=257,
                                 style={"marginRight": "20px", "backgroundColor": "#1a1a1a", "color": "#00FF00"}),
                        html.Label("Prime q:", style={"marginRight": "10px"}),
                        dcc.Input(id="rsa-input-q", type="number", value=263,
                                 style={"backgroundColor": "#1a1a1a", "color": "#00FF00"}),
                    ]),
                    html.Button("Generate Keys", id="rsa-generate-keys", n_clicks=0,
                               style={
                                   "backgroundColor": "#00FF00",
                                   "color": "black",
                                   "padding": "10px",
                                   "marginTop": "10px",
                                   "cursor": "pointer",
                               }),
                    html.Div(id="rsa-key-output", style={"marginTop": "10px", "wordBreak": "break-all"})
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
                                id="rsa-input-message",
                                placeholder="Enter message to encrypt...",
                                style={
                                    "width": "100%",
                                    "height": "100px",
                                    "backgroundColor": "#1a1a1a",
                                    "color": "#00FF00",
                                    "border": "1px solid #00FF00",
                                }
                            ),
                            html.Button("Encrypt", id="rsa-encrypt-button", n_clicks=0,
                                      style={
                                          "backgroundColor": "#00FF00",
                                          "color": "black",
                                          "padding": "10px",
                                          "marginTop": "10px",
                                          "width": "100%",
                                          "cursor": "pointer",
                                      }),
                            html.Div(id="rsa-encryption-output", 
                                    style={"marginTop": "10px", "wordBreak": "break-all"})
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
                                id="rsa-input-cipher",
                                placeholder="Enter message to decrypt...",
                                style={
                                    "width": "100%",
                                    "height": "100px",
                                    "backgroundColor": "#1a1a1a",
                                    "color": "#00FF00",
                                    "border": "1px solid #00FF00",
                                }
                            ),
                            html.Button("Decrypt", id="rsa-decrypt-button", n_clicks=0,
                                      style={
                                          "backgroundColor": "#00FF00",
                                          "color": "black",
                                          "padding": "10px",
                                          "marginTop": "10px",
                                          "width": "100%",
                                          "cursor": "pointer",
                                      }),
                            html.Div(id="rsa-decryption-output", 
                                    style={"marginTop": "10px", "wordBreak": "break-all"})
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
                        id="rsa-signature-message",
                        placeholder="Enter message to sign...",
                        style={
                            "width": "100%",
                            "height": "100px",
                            "backgroundColor": "#1a1a1a",
                            "color": "#00FF00",
                            "border": "1px solid #00FF00",
                        }
                    ),
                    html.Button("Sign Message", id="rsa-sign-button", n_clicks=0,
                               style={
                                   "backgroundColor": "#00FF00",
                                   "color": "black",
                                   "padding": "10px",
                                   "marginTop": "10px",
                                   "width": "100%",
                                   "cursor": "pointer",
                               }),
                    html.Div(id="rsa-signature-output", 
                            style={"marginTop": "10px", "wordBreak": "break-all"}),
                    html.Button("Verify Signature", id="rsa-verify-button", n_clicks=0,
                               style={
                                   "backgroundColor": "#00FF00",
                                   "color": "black",
                                   "padding": "10px",
                                   "marginTop": "10px",
                                   "width": "100%",
                                   "cursor": "pointer",
                               }),
                    html.Div(id="rsa-verification-output", 
                            style={"marginTop": "10px"})
                ]
            ),
            
            # Certificate Generation Section
            html.Div(
                style={
                    "backgroundColor": "#0D0D0D",
                    "padding": "20px",
                    "margin": "20px 0",
                    "border": "2px solid #00FF00",
                },
                children=[
                    html.H3("Certificate Generation", style={"color": "#00FF00"}),
                    html.Button("Generate Certificate", id="rsa-generate-cert", n_clicks=0,
                               style={
                                   "backgroundColor": "#00FF00",
                                   "color": "black",
                                   "padding": "10px",
                                   "width": "100%",
                                   "cursor": "pointer",
                               }),
                    html.Div(id="rsa-cert-output", 
                            style={"marginTop": "10px"})
                ]
            ),
            
            # Store components for maintaining state
            dcc.Store(id='rsa-public-key-store'),
            dcc.Store(id='rsa-private-key-store'),
            dcc.Store(id='rsa-signature-store'),
        ]
    )

# RSA Callbacks
@callback(
    [Output('rsa-key-output', 'children'),
     Output('rsa-public-key-store', 'data'),
     Output('rsa-private-key-store', 'data')],
    [Input('rsa-generate-keys', 'n_clicks')],
    [State('rsa-input-p', 'value'),
     State('rsa-input-q', 'value')]
)
def generate_keys(n_clicks, p, q):
    if n_clicks == 0:
        return "", None, None
    try:
        public_key, private_key = generer_cles(int(p), int(q))
        return (
            [
                html.Div(f"Public Key (e, n): {public_key}"),
                html.Div(f"Private Key (d, n): {private_key}")
            ],
            public_key,
            private_key
        )
    except Exception as e:
        return f"Error: {str(e)}", None, None

@callback(
    Output('rsa-encryption-output', 'children'),
    [Input('rsa-encrypt-button', 'n_clicks')],
    [State('rsa-input-message', 'value'),
     State('rsa-public-key-store', 'data')]
)
def encrypt_message(n_clicks, message, public_key):
    if n_clicks == 0 or not message or not public_key:
        return ""
    try:
        encrypted = chiffrer_message(message, public_key)
        return f"Encrypted message: {encrypted}"
    except Exception as e:
        return f"Error: {str(e)}"

@callback(
    Output('rsa-decryption-output', 'children'),
    [Input('rsa-decrypt-button', 'n_clicks')],
    [State('rsa-input-cipher', 'value'),
     State('rsa-private-key-store', 'data')]
)
def decrypt_message(n_clicks, cipher, private_key):
    if n_clicks == 0:
        return ""
    
    if not cipher:
        return html.Div("Please enter an encrypted message", style={"color": "#FF0000"})
    
    if not private_key:
        return html.Div("Please generate keys first", style={"color": "#FF0000"})
    
    try:
        # Debug information
        debug_info = []
        debug_info.append(f"Received cipher: {cipher}")
        debug_info.append(f"Private key: {private_key}")
        
        # Clean the input
        cipher = cipher.strip()
        
        # Check if the input contains the prefix "Encrypted message: "
        if "Encrypted message: " in cipher:
            cipher = cipher.replace("Encrypted message: ", "")
        
        # Attempt decryption
        decrypted = dechiffrer_message(cipher, private_key)
        
        return html.Div([
            html.Div(f"Decrypted message: {decrypted}", 
                    style={"color": "#00FF00", "marginBottom": "10px"}),
            html.Details([
                html.Summary("Debug Info", style={"cursor": "pointer"}),
                html.Div(
                    [html.Div(info) for info in debug_info],
                    style={"fontSize": "12px", "color": "#888888"}
                )
            ])
        ])
    except Exception as e:
        return html.Div([
            html.Div(f"Error: {str(e)}", style={"color": "#FF0000"}),
            html.Div("Make sure you:", style={"marginTop": "10px"}),
            html.Ul([
                html.Li("Have generated keys first"),
                html.Li("Pasted the complete encrypted message"),
                html.Li("Didn't modify the encrypted text")
            ], style={"color": "#FF8800"})
        ])

@callback(
    [Output('rsa-signature-output', 'children'),
     Output('rsa-signature-store', 'data')],
    [Input('rsa-sign-button', 'n_clicks')],
    [State('rsa-signature-message', 'value'),
     State('rsa-private-key-store', 'data')]
)
def sign_message(n_clicks, message, private_key):
    if n_clicks == 0 or not message or not private_key:
        return "", None
    try:
        signature = generer_signature(message, private_key)
        return f"Signature: {signature}", signature
    except Exception as e:
        return f"Error: {str(e)}", None

@callback(
    Output('rsa-verification-output', 'children'),
    [Input('rsa-verify-button', 'n_clicks')],
    [State('rsa-signature-message', 'value'),
     State('rsa-signature-store', 'data'),
     State('rsa-public-key-store', 'data')]
)
def verify_message(n_clicks, message, signature, public_key):
    if n_clicks == 0 or not message or not signature or not public_key:
        return ""
    try:
        is_valid = verifier_signature(message, signature, public_key)
        return html.Div(
            "Signature is valid" if is_valid else "Signature is invalid",
            style={"color": "#00FF00" if is_valid else "#FF0000"}
        )
    except Exception as e:
        return f"Error: {str(e)}"

@callback(
    Output('rsa-cert-output', 'children'),
    [Input('rsa-generate-cert', 'n_clicks')]
)
def generate_cert(n_clicks):
    if n_clicks == 0:
        return ""
    try:
        private_key, certificate = generer_certificat()
        sauvegarder_certificat(private_key, certificate)
        return [
            html.Div("Certificate generated successfully!"),
            html.Div("Files saved:"),
            html.Div("- certificat.pem"),
            html.Div("- cle_privee.pem")
        ]
    except Exception as e:
        return f"Error generating certificate: {str(e)}"