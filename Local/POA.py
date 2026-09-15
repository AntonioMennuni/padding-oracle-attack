from Cryptodome.Cipher import DES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
import os



# Configurazione

BLOCK_SIZE = 8  # DES usa blocchi da 8 byte
KEY = get_random_bytes(8) # Chiave DES (8 byte)



# Applicazione del padding PKCS#7 e cifratura con DES in CBC mode

def encrypt(plaintext):
    """
    Cifra il plaintext usando DES in CBC mode.
    Per ogni cifratura viene generato un nuovo IV casuale.
    """
    
    iv = get_random_bytes(BLOCK_SIZE) # IV casuale crittograficamente sicuro
    cipher = DES.new(KEY, DES.MODE_CBC, iv) #DES in CBC mode
    padded = pad(plaintext, BLOCK_SIZE) # PKCS#7
    #print(f"input con padding : {padded.hex()}")
    ciphertext = cipher.encrypt(padded) # cifratura del plaintex con DES in CBC mode 

    return iv, ciphertext



# Padding oracle che verifica se il plaintext è correttamente formattato in termini di padding PKCS#7

def padding_oracle(iv, ciphertext):
    """
    Oracle vulnerabile:
    restituisce True se il padding è valido,
    False altrimenti.
    """

    try:
        cipher = DES.new(KEY, DES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        unpad(plaintext, BLOCK_SIZE) # Se il padding non è valido viene sollevata un'eccezione

        return True

    except ValueError:
        return False
    


#Padding oracle attack

def padding_oracle_attack(iv, ciphertext):
    """
    Recupera il plaintext di un blocco cifrato
    usando il Padding Oracle Attack.
    """

    intermediate = bytearray(BLOCK_SIZE) # I = DEC_K(C1)
    recovered_plaintext = bytearray(BLOCK_SIZE) # array mutabile di 8 byte inizializzati a 0 in cui il plaintext recuperato verrà salvato

    for byte_index in range(BLOCK_SIZE - 1, -1, -1): # da 7 a 0
        print(f"brute force del byte {byte_index}")
        
        padding_value = BLOCK_SIZE - byte_index
        print(f"padding_value : {padding_value}")
        
        fake_iv = bytearray(iv) # copia modificabile dell’IV originale (Ci-1)

        # Modifica dei byte già trovati
        for j in range(byte_index + 1, BLOCK_SIZE):
            fake_iv[j] = intermediate[j] ^ padding_value

        if padding_value == 1 and byte_index > 0:
            fake_iv[byte_index - 1] ^= 0xFF

        # Bruteforce del byte corrente
        found = False

        for guess in range(256):
            fake_iv[byte_index] = guess

            if padding_oracle(bytes(fake_iv), ciphertext): # se il padding è correttamente formattato
                #print(f"fake_iv : {fake_iv.hex()}")

                # Calcolo intermediate byte
                intermediate_byte = guess ^ padding_value # I = guess xor padding_value
                intermediate[byte_index] = intermediate_byte

                # Plaintext byte
                plaintext_byte = intermediate_byte ^ iv[byte_index] # intermediate_byte xor valore del vero IV in posizione byte_index 
                recovered_plaintext[byte_index] = plaintext_byte

                print(f"Byte trovato in base 16: {plaintext_byte}") #stampa del plaintext byte in base 16
                print(f"{chr(plaintext_byte)}\n")

                found = True
                break

        if not found:
            print("Nessun byte trovato.")
            break

    return bytes(recovered_plaintext)



# main

if __name__ == "__main__":
    """
    il plaintext viene formattato in termini di padding con PKCS#7,
    viene cifrato con DES,
    viene diviso in blocchi da 8 byte
    e il padding oracle attack viene eseguito su ogni blocco per recuperare il plaintext originale
    """

    plaintext_input = input("Inserisci il plaintext: ")
    plaintext = plaintext_input.encode()
    #plaintext = b"ABCDEFGH"  # può essere qualunque lunghezza

    print(f"\nPlaintext originale: {plaintext}")

    iv, ciphertext = encrypt(plaintext)

    print(f"IV: {iv.hex()}")
    print(f"Ciphertext: {ciphertext.hex()}")


   # Suddivisione del ciphertext in blocchi da 8 byte

    blocks = [iv] + [
        ciphertext[i:i+BLOCK_SIZE]
        for i in range(0, len(ciphertext), BLOCK_SIZE)
    ]

    
    print("\n Blocchi:")
    for i, b in enumerate(blocks):
        print(i, b.hex())



    # Inizio del padding oracle attack

    recovered = b""

    for i in range(1, len(blocks)):

        prev_block = blocks[i - 1]
        curr_block = blocks[i]

        print(f"\nDecifratura del blocco {i}\n")

        recovered_block = padding_oracle_attack(prev_block, curr_block)

        #ricostruzione del plaintext finale mettendo insieme i blocchi recuperati uno dopo l’altro
        recovered += recovered_block


    # Rimozione del padding

    recovered = unpad(recovered, BLOCK_SIZE)
    print("\n[+] Plaintext recuperato:")
    print(recovered)