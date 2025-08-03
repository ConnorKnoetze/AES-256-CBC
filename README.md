# Password Manager in C

This project is a password manager implemented in C. It uses AES-256 encryption in CBC mode to securely store passwords, with Base64 encoding for the encrypted output.

## Features

- AES-256 encryption with CBC mode.
- Base64 encoding for encrypted data.
- Secure key and initialization vector (IV) generation using OpenSSL.
- Deterministic testing with fixed keys and IVs (for development).
- Password storage in a file (`password.txt`).

## Files

- `main.c`: Contains the main logic for the password manager, including user input handling and password storage.
- `encrypt.c`: Implements AES encryption, Base64 encoding, and related cryptographic functions.
- `password.txt`: Stores the encrypted and Base64-encoded passwords.

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
- Ensure the `password.txt` file is stored securely, as it contains sensitive information.
