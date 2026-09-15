# Padding Oracle Attack

Practical implementations of a **Padding Oracle Attack (POA)** against
**DES in CBC mode with PKCS#7 padding**.

This project demonstrates how a padding oracle vulnerability can be
exploited to recover plaintext from ciphertext without knowledge of the
encryption key.

The attack is implemented in two different configurations:

- **Local implementation** — the vulnerable oracle and the attacker run
  on the same machine.
- **Client-server implementation** — a vulnerable server acts as the
  padding oracle, while one or more clients remotely perform the attack
  over a local network.

---

## Overview

A Padding Oracle Attack is a cryptographic attack that exploits an
implementation that reveals whether the padding of a decrypted ciphertext
is valid or invalid.

In this project, the vulnerable encryption scheme uses:

- **DES** as the block cipher
- **CBC (Cipher Block Chaining)** as the encryption mode
- **PKCS#7** as the padding scheme

The attacker does not need to know the secret encryption key. Instead,
the attack relies on the different responses returned by the padding
oracle when modified ciphertexts are submitted.

The attack works by modifying the previous ciphertext block (or the IV
when attacking the first block) and systematically testing possible byte
values. By observing whether the resulting padding is valid, the attacker
can recover the intermediate state and consequently the original
plaintext.

## Project structure

## Project Structure

```text
├── local/
│   └── POA.py
├── client-server/
│   ├── server.py
│   └── client.py
├── POA_documentation.pdf
├── requirements.txt
└── README.md
```

## Setup

For a more in-depth analysis of the attack, the attack setup, and the code implementation, please refer to the POA_documentation.pdf file.

