
# AES-256-CBC Encryption & Decryption Tool

**Note:** This branch is specifically tailored for integration with the pass-manager app. It may contain modifications or interfaces designed to work seamlessly with that application.

This project is a general-purpose AES encryption and decryption tool implemented in C. It uses AES-256 in CBC mode for secure encryption and decryption of data, with Base64 encoding for easy file handling. The tool is designed to work with files and can be used from any directory containing a `textfiles` folder with the required input files.

## Features

- AES-256 encryption and decryption in CBC mode
- Base64 encoding/decoding for encrypted data
- File-based input and output for keys, IVs, plaintext, and ciphertext
- Modular structure with separate encryption and decryption executables
- Cross-platform support (Windows, Linux)
- Easy integration into scripts or other tools

## Directory Structure

- `encrypt/` — Source and executable for encryption
- `decrypt/` — Source and executable for decryption
- `textfiles/` — Input/output files (keys, IVs, plaintext, ciphertext, etc.)
- `build/` — (Optional) Pre-built binaries and test files

## How to Build

You can build the encryption and decryption binaries using GCC. OpenSSL development libraries are required.

### Build Encryption

```bash
gcc -o encrypt/encrypt encrypt/encrypt.c -I. -lssl -lcrypto
```

### Build Decryption

```bash
gcc -o decrypt/tester decrypt/tester.c -I. -lssl -lcrypto
```

### Requirements

- GCC compiler (MinGW or MSYS2 recommended for Windows)
- OpenSSL development libraries (`-lssl -lcrypto`)

## Usage

All input and output files are expected in the `textfiles` directory in your current working directory.

### Encryption

Run the encryption executable to encrypt data. Example:

```bash
encrypt/encrypt
```

This will read plaintext and key/IV files from `textfiles/`, perform encryption, and write the ciphertext to `textfiles/output.txt` (or similar).

### Decryption

Run the decryption executable to decrypt data. Example:

```bash
decrypt/tester
```

This will read ciphertext and key/IV files from `textfiles/`, perform decryption, and print the plaintext to stdout and write it to `textfiles/output.txt`.

For application integration, you can uncomment the `MAINACTIVE` macro in the source code. This allows you to call `decrypt.exe` directly and pass the required arguments (e.g., the actual contents of the required inputs) as command-line parameters. If `MAINACTIVE` is not enabled, the `tester` executable will handle input and output directly from the `textfiles` directory.

### Example: Calling `decrypt.exe` with Arguments

If the `MAINACTIVE` macro is enabled, you can call `decrypt.exe` as follows:

```bash
decrypt.exe <masterkey> <key> <keyiv> <ciphertext> <passiv> <msize> <ksize> <keyivsize> <csize> <passivsize>
```

For example:

```bash
decrypt.exe "my_master_key" "my_key" "my_key_iv" "encrypted_data" "passiv_data" 32 32 16 128 16
```

This will decrypt the ciphertext using the provided inputs and sizes, then output the plaintext to stdout and write it to `textfiles/output.txt`.

## Notes

- All file paths are relative to the `textfiles` directory, so you can run the executables from any directory containing this folder.
- The tool uses PKCS#7 padding and Base64 encoding for output.
- For testing, deterministic keys and IVs can be enabled by defining the `USE_SEEDED_RANDOM` macro.
- Ensure all sensitive files (keys, IVs, plaintext, ciphertext) are stored securely.
- **Important Note:** `decrypt.exe` strictly requires AES-256 standard input and cannot handle other key sizes. The inputs must come directly from the contents of the files produced by the encryption process to ensure compatibility and correctness.
