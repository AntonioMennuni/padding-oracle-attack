from Cryptodome.Cipher import DES 
from Cryptodome.Random import get_random_bytes 
from Cryptodome.Util.Padding import pad, unpad 
import os 
 
 
 
# Configuration 
 
BLOCK_SIZE = 8  # DES uses 8-byte blocks 
KEY = get_random_bytes(8) # DES key (8 bytes) 
 
 
 
# PKCS#7 padding and encryption using DES in CBC mode 
 
def encrypt(plaintext): 
    """ 
    Encrypts the plaintext using DES in CBC mode. 
    A new random IV is generated for each encryption. 
    """ 
     
    iv = get_random_bytes(BLOCK_SIZE) # Cryptographically secure random IV 
    cipher = DES.new(KEY, DES.MODE_CBC, iv) # DES in CBC mode 
    padded = pad(plaintext, BLOCK_SIZE) # PKCS#7 
    #print(f"input con padding : {padded.hex()}") 
    ciphertext = cipher.encrypt(padded) # Encrypts the plaintext using DES in CBC mode  
 
    return iv, ciphertext 
 
 
 
# Padding oracle that checks whether the plaintext is correctly formatted in terms of PKCS#7 padding 
 
def padding_oracle(iv, ciphertext): 
    """ 
    Vulnerable oracle: 
    returns True if the padding is valid, 
    False otherwise. 
    """ 
 
    try: 
        cipher = DES.new(KEY, DES.MODE_CBC, iv) 
        plaintext = cipher.decrypt(ciphertext) 
        unpad(plaintext, BLOCK_SIZE) # An exception is raised if the padding is invalid 
 
        return True 
 
    except ValueError: 
        return False 
     
 
 
# Padding oracle attack 
 
def padding_oracle_attack(iv, ciphertext): 
    """ 
    Recovers the plaintext of an encrypted block 
    using the Padding Oracle Attack. 
    """ 
 
    intermediate = bytearray(BLOCK_SIZE) # I = DEC_K(C1) 
    recovered_plaintext = bytearray(BLOCK_SIZE) # mutable array of 8 bytes initialized to 0 in which the recovered plaintext will be stored 
 
    for byte_index in range(BLOCK_SIZE - 1, -1, -1): # from 7 to 0 
        print(f"brute force of byte {byte_index}") 
         
        padding_value = BLOCK_SIZE - byte_index 
        print(f"padding_value : {padding_value}") 
         
        fake_iv = bytearray(iv) # modifiable copy of the original IV (Ci-1) 
 
        # Modify the bytes already found 
        for j in range(byte_index + 1, BLOCK_SIZE): 
            fake_iv[j] = intermediate[j] ^ padding_value 
 
        if padding_value == 1 and byte_index > 0: 
            fake_iv[byte_index - 1] ^= 0xFF 
 
        # Brute-force the current byte 
        found = False 
 
        for guess in range(256): 
            fake_iv[byte_index] = guess 
 
            if padding_oracle(bytes(fake_iv), ciphertext): # if the padding is correctly formatted 
                #print(f"fake_iv : {fake_iv.hex()}") 
 
                # Calculate intermediate byte 
                intermediate_byte = guess ^ padding_value # I = guess xor padding_value 
                intermediate[byte_index] = intermediate_byte 
 
                # Plaintext byte 
                plaintext_byte = intermediate_byte ^ iv[byte_index] # intermediate_byte xor value of the actual IV at byte_index  
                recovered_plaintext[byte_index] = plaintext_byte 
 
                print(f"Byte found in base 16: {plaintext_byte}") # prints the plaintext byte in hexadecimal 
                print(f"{chr(plaintext_byte)}\n") 
 
                found = True 
                break 
 
        if not found: 
            print("No byte found.") 
            break 
 
    return bytes(recovered_plaintext) 
 
 
 
# main 
 
if __name__ == "__main__": 
    """ 
    The plaintext is formatted using PKCS#7 padding, 
    encrypted with DES, 
    divided into 8-byte blocks, 
    and the padding oracle attack is performed on each block to recover the original plaintext 
    """ 
 
    plaintext_input = input("Insert the plaintext: ") 
    plaintext = plaintext_input.encode() 
    #plaintext = b"ABCDEFGH"  # can be of any length 
 
    print(f"\nOriginal plaintext: {plaintext}") 
 
    iv, ciphertext = encrypt(plaintext) 
 
    print(f"IV: {iv.hex()}") 
    print(f"Ciphertext: {ciphertext.hex()}") 
 
 
   # Split the ciphertext into 8-byte blocks 
 
    blocks = [iv] + [ 
        ciphertext[i:i+BLOCK_SIZE] 
        for i in range(0, len(ciphertext), BLOCK_SIZE) 
    ] 
 
     
    print("\n Blocchi:") 
    for i, b in enumerate(blocks): 
        print(i, b.hex()) 
 
 
 
    # Start of the padding oracle attack 
 
    recovered = b"" 
 
    for i in range(1, len(blocks)): 
 
        prev_block = blocks[i - 1] 
        curr_block = blocks[i] 
 
        print(f"\n decryption of block {i}\n") 
 
        recovered_block = padding_oracle_attack(prev_block, curr_block) 
 
        # Reconstruct the final plaintext by putting the recovered blocks together one after another 
        recovered += recovered_block 
 
 
    # Remove padding 
 
    recovered = unpad(recovered, BLOCK_SIZE) 
    print("\n[+] Recovered plaintext:") 
    print(recovered)