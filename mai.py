import dash
from dash import html, dcc
from dash.dependencies import Input, Output, State
from src.RSA import (
    generate_keys,
    encrypt_message,
    decrypt_message,
    sign_message,
    verify_signature,
    generate_certificate,
)
from src.styles import styles  # Import the styles dictionary

# Initialize Dash app
app =dash.Dash(__name__)
server = app.server  # Required for deployment if needed

# Define the layout
app.layout = html.Div(
    style=styles["main_container"],
    children=[
        html.H1("RSA Cryptosystem Dashboard", style=styles["header"]),
        html.Div(
            style=styles["content_container"],
            children=[
                html.Div(
                    style=styles["box"],
                    children=[
                        html.H2("Step 1: Generate RSA Keys"),
                        html.Label("Enter p (prime number):"),
                        dcc.Input(id="input-p", type="number", placeholder="Prime number p", style=styles["input"]),
                        html.Label("Enter q (prime number):", style={"marginTop": "10px"}),
                        dcc.Input(id="input-q", type="number", placeholder="Prime number q", style=styles["input"]),
                        html.Button("Generate Keys", id="generate-keys-button", style=styles["button"]),
                        html.Div(id="keys-output", style={"marginTop": "20px"}),
                    ],
                ),
                html.Div(
                    style=styles["box"],
                    children=[
                        html.H2("Step 2: Encrypt a Message"),
                        html.Label("Message to encrypt:"),
                        dcc.Textarea(id="encrypt-message", style=styles["textarea"]),
                        html.Button("Encrypt Message", id="encrypt-button", style=styles["button"]),
                        html.Div(id="encrypt-output", style={"marginTop": "20px"}),
                    ],
                ),
                html.Div(
                    style=styles["box"],
                    children=[
                        html.H2("Step 3: Decrypt a Message"),
                        html.Label("Encrypted Base64 Message:"),
                        dcc.Textarea(id="decrypt-message", style=styles["textarea"]),
                        html.Button("Decrypt Message", id="decrypt-button", style=styles["button"]),
                        html.Div(id="decrypt-output", style={"marginTop": "20px"}),
                    ],
                ),
            ],
        ),
        html.Div(
            style=styles["content_container"],
            children=[
                html.Div(
                    style=styles["box"],
                    children=[
                        html.H2("Step 4: Sign a Message"),
                        html.Label("Message to sign:"),
                        dcc.Textarea(id="sign-message", style=styles["textarea"]),
                        html.Button("Sign Message", id="sign-button", style=styles["button"]),
                        html.Div(id="signature-output", style={"marginTop": "20px"}),
                    ],
                ),
                html.Div(
                    style=styles["box"],
                    children=[
                        html.H2("Step 5: Verify Signature"),
                        html.Label("Message:"),
                        dcc.Textarea(id="verify-message", style={"width": "100%", "marginBottom": "10px"}),
                        html.Label("Signature:"),
                        dcc.Input(id="input-signature", style=styles["input"]),
                        html.Button("Verify Signature", id="verify-button", style=styles["button"]),
                        html.Div(id="verify-output", style={"marginTop": "20px"}),
                    ],
                ),
                html.Div(
                    style=styles["box"],
                    children=[
                        html.H2("Step 6: Generate Certificate"),
                        html.Label("Common Name (CN):"),
                        dcc.Input(id="cert-cn", value="Samir Ziani", style=styles["input"]),
                        html.Button("Generate Certificate", id="cert-button", style=styles["button"]),
                        html.Div(id="cert-output", style={"marginTop": "20px"}),
                    ],
                ),
            ],
        ),
    ],
)


@app.callback(
    Output("keys-output", "children"),
    Input("generate-keys-button", "n_clicks"),
    State("input-p", "value"),
    State("input-q", "value"),
)
def generate_keys_callback(n_clicks, p, q):
    if not n_clicks or not p or not q:
        return "Please enter valid prime numbers for p and q."
    public_key, private_key = generate_keys(int(p), int(q))
    return f"Public Key: {public_key}, Private Key: {private_key}"

@app.callback(
    Output("encrypt-output", "children"),
    Input("encrypt-button", "n_clicks"),
    State("encrypt-message", "value"),
    State("input-p", "value"),
    State("input-q", "value"),
)
def encrypt_callback(n_clicks, message, p, q):
    if not n_clicks or not message or not p or not q:
        return "Please provide a message and keys to encrypt."
    public_key, _ = generate_keys(int(p), int(q))
    encrypted_message = encrypt_message(message, public_key)
    return encrypted_message

@app.callback(
    Output("decrypt-output", "children"),
    Input("decrypt-button", "n_clicks"),
    State("decrypt-message", "value"),
    State("input-p", "value"),
    State("input-q", "value"),
)
def decrypt_callback(n_clicks, encrypted_message, p, q):
    if not n_clicks or not encrypted_message or not p or not q:
        return "Please provide a Base64 message and keys to decrypt."
    _, private_key = generate_keys(int(p), int(q))
    decrypted_message = decrypt_message(encrypted_message, private_key)
    return decrypted_message

@app.callback(
    Output("signature-output", "children"),
    Input("sign-button", "n_clicks"),
    State("sign-message", "value"),
    State("input-p", "value"),
    State("input-q", "value"),
)
def sign_callback(n_clicks, message, p, q):
    if not n_clicks or not message or not p or not q:
        return "Please provide a message and keys to sign."
    _, private_key = generate_keys(int(p), int(q))
    signature = sign_message(message, private_key)
    return f"Signature: {signature}"

@app.callback(
    Output("verify-output", "children"),
    Input("verify-button", "n_clicks"),
    State("verify-message", "value"),
    State("input-signature", "value"),
    State("input-p", "value"),
    State("input-q", "value"),
)
def verify_callback(n_clicks, message, signature, p, q):
    if not n_clicks or not message or not signature or not p or not q:
        return "Please provide all inputs to verify the signature."
    public_key, _ = generate_keys(int(p), int(q))
    is_valid = verify_signature(message, int(signature), public_key)
    return f"Signature Valid: {is_valid}"

@app.callback(
    Output("cert-output", "children"),
    Input("cert-button", "n_clicks"),
    State("cert-cn", "value"),
    State("input-p", "value"),
    State("input-q", "value"),
)
def cert_callback(n_clicks, common_name, p, q):
    if not n_clicks or not common_name or not p or not q:
        return "Please provide all inputs to generate a certificate."
    public_key, private_key = generate_keys(int(p), int(q))
    certificate = generate_certificate(common_name, private_key, public_key)
    return f"Certificate:\n{certificate}"

if __name__ == "__main__":
    app.run_server(debug=True)

