# Password Manager in C

This project is a password manager implemented in C. It uses AES-256 encryption in CBC mode to securely store passwords, with Base64 encoding for the encrypted output. The program also supports secure key storage and deterministic testing for development purposes.

## Features

- AES-256 encryption with CBC mode.
- Base64 encoding for encrypted data.
- Secure key and initialization vector (IV) generation using OpenSSL.
- Deterministic testing with fixed keys and IVs (for development).
- Password storage in a file (`password.txt`).
- Secure storage of encryption keys in a file (`keys.txt`).
- Master key management using a file (`masterkey.txt`).

## Files

- `main.c`: Contains the main logic for the password manager, including user input handling and password storage.
- `encrypt.c`: Implements AES encryption, Base64 encoding, key storage, and related cryptographic functions.
- `password.txt`: Stores the encrypted and Base64-encoded passwords.
- `keys.txt`: Stores the Base64-encoded encryption keys.
- `masterkey.txt`: Stores the master key used for encrypting the encryption keys.

## How to Build and Run

1. Build the program using the provided Makefile:

   ```bash
   make
   ```

2. Run the program with the following command:

   ```bash
   ./pass_manager <username> <password>
   ```

## Requirements

- GCC compiler installed on your system.
- OpenSSL library for cryptographic functions.

## Notes

- For testing purposes, deterministic keys and IVs can be enabled by defining the `USE_SEEDED_RANDOM` macro in the code.
- Ensure the `password.txt`, `keys.txt`, and `masterkey.txt` files are stored securely, as they contain sensitive information.
- The program uses PKCS#7 padding for encryption and Base64 encoding for output.
