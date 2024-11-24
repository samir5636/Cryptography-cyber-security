import dash
from dash import html, dcc
from dash.dependencies import Input, Output, State
from src.RSA import generate_keys, encrypt_message, decrypt_message

# Initialize Dash app
app = dash.Dash(__name__)

# Define the layout
app.layout = html.Div(
    style={
        "backgroundColor": "#000",  # Black background
        "color": "#00FF00",  # Neon green text
        "fontFamily": "Courier New, monospace",  # Hacker-style font
        "margin": "0",
        "height": "100vh",  # Full viewport height
        "display": "flex",
        "flexDirection": "column",
    },
    children=[
        html.H1(
            "RSA Cryptosystem Dashboard",
            style={"textAlign": "center", "color": "#00FF00", "margin": "20px 0"}
        ),
        html.Div(
            style={
                "display": "flex",
                "flex": "1",
                "justifyContent": "space-between",
                "padding": "20px",
                "gap": "20px",
            },
            children=[
                html.Div(
                    style={
                        "flex": "1",
                        "backgroundColor": "#0D0D0D",
                        "padding": "15px",
                        "border": "2px solid #00FF00",
                        "display": "flex",
                        "flexDirection": "column",
                    },
                    children=[
                        html.H2("Step 1: Generate RSA Keys"),
                        html.Label("Enter p (prime number):"),
                        dcc.Input(id="input-p", type="number", value=257, style={"width": "100%", "marginBottom": "10px"}),
                        html.Label("Enter q (prime number):"),
                        dcc.Input(id="input-q", type="number", value=263, style={"width": "100%", "marginBottom": "10px"}),
                        html.Button(
                            "Generate Keys",
                            id="generate-keys-button",
                            style={
                                "width": "100%",
                                "backgroundColor": "#00FF00",
                                "border": "none",
                                "color": "#000",
                                "padding": "10px",
                                "cursor": "pointer",
                            },
                        ),
                        html.Div(id="keys-output", style={"marginTop": "20px"})
                    ],
                ),
                html.Div(
                    style={
                        "flex": "1",
                        "backgroundColor": "#0D0D0D",
                        "padding": "15px",
                        "border": "2px solid #00FF00",
                        "display": "flex",
                        "flexDirection": "column",
                    },
                    children=[
                        html.H2("Step 2: Encrypt a Message"),
                        html.Label("Message to encrypt:"),
                        dcc.Textarea(
                            id="input-message",
                            value="ziani\nsamir\n",
                            style={"width": "100%", "height": "100px", "marginBottom": "10px"},
                        ),
                        html.Button(
                            "Encrypt Message",
                            id="encrypt-button",
                            style={
                                "width": "100%",
                                "backgroundColor": "#00FF00",
                                "border": "none",
                                "color": "#000",
                                "padding": "10px",
                                "cursor": "pointer",
                            },
                        ),
                        html.Div(id="encrypted-output", style={"marginTop": "20px"})
                    ],
                ),
                html.Div(
                    style={
                        "flex": "1",
                        "backgroundColor": "#0D0D0D",
                        "padding": "15px",
                        "border": "2px solid #00FF00",
                        "display": "flex",
                        "flexDirection": "column",
                    },
                    children=[
                        html.H2("Step 3: Decrypt a Message"),
                        html.Button(
                            "Decrypt Message",
                            id="decrypt-button",
                            style={
                                "width": "100%",
                                "backgroundColor": "#00FF00",
                                "border": "none",
                                "color": "#000",
                                "padding": "10px",
                                "cursor": "pointer",
                            },
                        ),
                        html.Div(id="decrypted-output", style={"marginTop": "20px"})
                    ],
                ),
            ],
        ),
        html.Footer(
            style={
                "textAlign": "center",
                "padding": "10px 0",
                "color": "#00FF00",
                "fontSize": "14px",
                "borderTop": "1px solid #00FF00",
            },
            children=[
                html.Span("Developed by Samir Ziani - Hacker Style 🚀"),
                html.A(
                    " GitHub ",
                    href="https://github.com/samir-ziani",  # Replace with your GitHub URL
                    style={"color": "#00FF00", "textDecoration": "none"},
                    target="_blank",
                ),
            ],
        ),
    ],
)

# Callbacks for interactivity
@app.callback(
    Output("keys-output", "children"),
    Input("generate-keys-button", "n_clicks"),
    State("input-p", "value"),
    State("input-q", "value"),
)
def generate_keys_callback(n_clicks, p, q):
    if not n_clicks:
        return ""
    public_key, private_key = generate_keys(p, q)
    return html.Div([
        html.P(f"Public Key: {public_key}"),
        html.P(f"Private Key: {private_key}")
    ])


@app.callback(
    Output("encrypted-output", "children"),
    Input("encrypt-button", "n_clicks"),
    State("input-p", "value"),
    State("input-q", "value"),
    State("input-message", "value"),
)
def encrypt_message_callback(n_clicks, p, q, message):
    if not n_clicks:
        return ""
    public_key, _ = generate_keys(p, q)
    encrypted_message = encrypt_message(message, public_key)
    return html.P(f"Encrypted Message (Base64): {encrypted_message}")


@app.callback(
    Output("decrypted-output", "children"),
    Input("decrypt-button", "n_clicks"),
    State("input-p", "value"),
    State("input-q", "value"),
    State("input-message", "value"),
)
def decrypt_message_callback(n_clicks, p, q, message):
    if not n_clicks:
        return ""
    public_key, private_key = generate_keys(p, q)
    encrypted_message = encrypt_message(message, public_key)
    decrypted_message = decrypt_message(encrypted_message, private_key)
    return html.P(f"Decrypted Message: {decrypted_message}")


if __name__ == "__main__":
    app.run_server(debug=True)
