from flask import Flask, request, jsonify 
from Cryptodome.Cipher import DES 
from Cryptodome.Random import get_random_bytes 
from Cryptodome.Util.Padding import pad, unpad 
import base64 
 
 
# Configuration 
 
app = Flask(__name__) 
BLOCK_SIZE = 8 
KEY = get_random_bytes(8) 
SECRET_MESSAGE = b"Hello guys" # Message to encrypt 
 
 
 
# Applying PKCS#7 padding and encrypting with DES in CBC mode 
 
def encrypt_message(message: bytes): 
    """ 
    Encrypts the plaintext using DES in CBC mode. 
    A new random IV is generated for each encryption. 
    """ 
 
    iv = get_random_bytes(BLOCK_SIZE) # Cryptographically secure random IV 
    cipher = DES.new(KEY, DES.MODE_CBC, iv) # DES in CBC mode 
    padded = pad(message, BLOCK_SIZE) # PKCS#7 
    ciphertext = cipher.encrypt(padded) # Encrypts the plaintext with DES in CBC mode 
 
    return iv + ciphertext 
 
 
 
# Token for communication with the client 
TOKEN = encrypt_message(SECRET_MESSAGE) 
TOKEN_B64 = base64.b64encode(TOKEN).decode() 
 
 
 
# The server receives the token from the client 
 
@app.route("/token", methods=["GET"]) 
def get_token(): 
    return jsonify({ 
        "token": TOKEN_B64 
    }) 
 
 
 
# The server sends messages to the client 
 
@app.route("/decrypt", methods=["POST"]) 
def decrypt(): 
 
    data = request.json 
 
    try: 
 
        raw = base64.b64decode(data["token"]) 
        iv = raw[:BLOCK_SIZE] 
        ciphertext = raw[BLOCK_SIZE:] 
        cipher = DES.new(KEY, DES.MODE_CBC, iv) 
        plaintext = cipher.decrypt(ciphertext) 
        unpad(plaintext, BLOCK_SIZE) 
 
        # Returns status code 200 if the padding is valid 
        return jsonify({ 
            "status": "valid padding" 
        }), 200 
 
    except ValueError: 
         
        # Returns status code 403 if the padding is invalid 
        return jsonify({ 
            "status": "invalid padding" 
        }), 403 
     
 
 
# Initialize the application 
 
if __name__ == "__main__": 
 
    app.run( 
        host="0.0.0.0", # Allows external computers (on the same network) to connect 
        port=5000, 
        threaded = True # Explicitly creates a separate thread for each client request 
    )
