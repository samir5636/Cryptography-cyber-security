from dash import Dash, html, dcc, callback, Output, Input, State
import base64
from RSA import (
    generer_cles, chiffrer_message, dechiffrer_message,
    generer_signature, verifier_signature, generer_certificat,
    sauvegarder_certificat
)
from RSAUI import create_rsa_layout
from ELGamalUI import create_elgamal_layout

# Initialize the Dash app
app = Dash(__name__, suppress_callback_exceptions=True)

# Define the layout
app.layout = html.Div(
    style={
        "backgroundColor": "#000",
        "color": "#00FF00",
        "fontFamily": "Courier New, monospace",
        "minHeight": "100vh",
    },
    children=[
        # Header with Navigation
        html.Div(
            style={
                "backgroundColor": "#0D0D0D",
                "padding": "20px",
                "borderBottom": "2px solid #00FF00",
                "marginBottom": "20px",
            },
            children=[
                html.H1("Cryptography Dashboard", 
                        style={"textAlign": "center", "color": "#00FF00", "marginBottom": "20px"}),
                # Navigation Bar
                html.Div(
                    style={
                        "display": "flex",
                        "justifyContent": "center",
                        "gap": "20px",
                    },
                    children=[
                        dcc.Link(
                            "RSA",
                            href="/rsa",
                            style={
                                "backgroundColor": "#00FF00",
                                "color": "black",
                                "padding": "10px 20px",
                                "textDecoration": "none",
                                "borderRadius": "5px",
                            }
                        ),
                        dcc.Link(
                            "ElGamal",
                            href="/elgamal",
                            style={
                                "backgroundColor": "#00FF00",
                                "color": "black",
                                "padding": "10px 20px",
                                "textDecoration": "none",
                                "borderRadius": "5px",
                            }
                        ),
                    ]
                ),
            ]
        ),
        
        # Content area
        html.Div(id='page-content', style={"padding": "20px"}),
        
        # URL Location store
        dcc.Location(id='url', refresh=False),
    ]
)

# Callback to handle page routing
@app.callback(
    Output('page-content', 'children'),
    [Input('url', 'pathname')]
)
def display_page(pathname):
    if pathname == '/rsa':
        return create_rsa_layout()
    elif pathname == '/elgamal':
        return create_elgamal_layout()
    else:
        # Default to RSA
        return create_rsa_layout()

# Include all your existing callbacks here
# Make sure to modify the callback IDs if needed to avoid conflicts

if __name__ == '__main__':
    app.run_server(debug=True)