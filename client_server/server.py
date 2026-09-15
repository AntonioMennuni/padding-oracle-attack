from flask import Flask, request, jsonify
from Cryptodome.Cipher import DES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import base64


# Configurazione

app = Flask(__name__)
BLOCK_SIZE = 8
KEY = get_random_bytes(8)
SECRET_MESSAGE = b"Hello professor Dini" #Messaggio da cifrare



# Applicazione del padding PKCS#7 e cifratura con DES in CBC mode

def encrypt_message(message: bytes):
    """
    Cifra il plaintext usando DES in CBC mode.
    Per ogni cifratura viene generato un nuovo IV casuale.
    """

    iv = get_random_bytes(BLOCK_SIZE) # IV casuale crittograficamente sicuro
    cipher = DES.new(KEY, DES.MODE_CBC, iv) #DES in CBC mode
    padded = pad(message, BLOCK_SIZE) # PKCS#7
    ciphertext = cipher.encrypt(padded) # cifratura del plaintex con DES in CBC mode

    return iv + ciphertext



# token per la comunicazione con i(l) client
TOKEN = encrypt_message(SECRET_MESSAGE)
TOKEN_B64 = base64.b64encode(TOKEN).decode()



# Il server riceve il token dal client

@app.route("/token", methods=["GET"])
def get_token():
    return jsonify({
        "token": TOKEN_B64
    })



# Il server invia messaggi al client

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

        # restituisce codice 200 se il padding è valido
        return jsonify({
            "status": "valid padding"
        }), 200

    except ValueError:
        
        # restituisce codice 403 se il padding non è valido
        return jsonify({
            "status": "invalid padding"
        }), 403
    


#Inizializza l'app

if __name__ == "__main__":

    app.run(
        host="0.0.0.0", # Permette a computer esterni (nella stessa rete) di connettersi
        port=5000,
        threaded = True # Crea esplicitamente un thread separato per ogni richiesta client
    )