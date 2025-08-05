#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../decrypt/decode64.h"
#include "encode64.h"

#include "AES_Encrypt.h"

#include <openssl/rand.h>
#include <openssl/evp.h>

// Declare functions out of scope of their callers
void cbc_init(unsigned char (*plaintext)[4][4], unsigned char* iv);
void cbc_main(unsigned char (*plaintext)[4][4], unsigned char prev[4][4]);
int encrypt(char** storePass, unsigned char* key, unsigned char* iv);

struct passwords 
{
    char *username;
    char *password;
};

// Define this macro to enable seeded random values for testing purposes comment out to return to random.
#define USE_SEEDED_RANDOM

#ifdef USE_SEEDED_RANDOM

// Function to seed the OpenSSL random number generator for testing purposes.
void seed_random() {
    const unsigned char seed[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}; // Constant seed for reproducibility.
    RAND_seed(seed, sizeof(seed));
}

// Function to generate a fixed initialization vector (IV) for testing purposes.
void gen_iv(unsigned char* iv){
    const unsigned char fixed_iv[16] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
    memcpy(iv, fixed_iv, 16);
}

// Function to generate a fixed encryption key for testing purposes.
void gen_key(unsigned char* key, int key_size){
    const unsigned char fixed_key[32] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
    };
    memcpy(key, fixed_key, key_size / 8);
}
#else
// Function to generate a random initialization vector (IV) using OpenSSL's RAND_bytes.
// The IV is critical for ensuring that the same plaintext encrypts to different ciphertexts.
void gen_iv(unsigned char* iv){
#ifdef USE_SEEDED_RANDOM
    seed_random();
#endif
    if (RAND_bytes(iv, 16) != 1) {
        fprintf(stderr, "Error generating IV\n");
        exit(EXIT_FAILURE);
    }
}

// Function to generate a random encryption key of the specified size (in bits).
// Uses OpenSSL's RAND_bytes to ensure cryptographic randomness.
void gen_key(unsigned char* key, int key_size){
#ifdef USE_SEEDED_RANDOM
    seed_random();
#endif
    int key_size_bytes = key_size / 8; // Convert key size from bits to bytes.
    if (RAND_bytes(key, key_size_bytes) != 1){
        fprintf(stderr, "Error generating random key\n");
        exit(EXIT_FAILURE);
    }
}
#endif


// Function to pad the plaintext to a multiple of 16 bytes.
// Padding is necessary for AES, which operates on fixed-size blocks.
void getPadded(char** storePass) {
    int pad = strlen(*storePass) % 16;
    if (pad == 0) {
        pad = 16;
    } else {
        pad = 16 - pad;
    }

    // Allocate memory for the padding and append it to the plaintext.
    char *padding = (char*)malloc(pad + 1);
    for (int i = 0; i < pad; i++) {
        padding[i] = (char)(pad); // Use PKCS#7 padding scheme.
    }
    padding[pad] = '\0';

    char *final_string = (char*)realloc(*storePass, strlen(*storePass) + strlen(padding) + 1);
    strcat(final_string, padding);

    free(padding);

    *storePass = final_string;
}

// Function to store key used in instance to encrypt password.
// Using a Master key
void StoreKey(unsigned char* key) {
    char* key_array = (char*)malloc(45);

    char *stored_key = (char *)malloc(33); // Allocate memory for the key (32 bytes + null terminator).
    if (stored_key == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    memcpy(stored_key, key, 32);
    stored_key[32] = '\0'; // Null-terminate the string.

    FILE *file = fopen("./textfiles/masterkey.txt", "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    while (fgets(key_array, 45, file) != NULL) {}
    fclose(file);

    size_t size = (3 * 45) / 4 - 2; // Size of decoded master key

    unsigned char *decoded_key_array = (unsigned char *)malloc(size);
    if (decoded_key_array == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        free(key_array);
        return;
    }

    unsigned char iv[16];
    gen_iv(iv);
    encrypt(&stored_key, decoded_key_array, iv); 

    int new_size = encode64(&stored_key, 32);

    FILE *file1 = fopen("./textfiles/key.txt", "w");
    if (file1 == NULL) {
        free(key_array);
        free(decoded_key_array);
        free(stored_key); // Free the allocated memory after use.
        return;
    }

    fwrite(stored_key, 1, new_size, file1);
    fclose(file1);

    char *stored_iv = (char*)malloc(16);
    if (stored_iv == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    memcpy(stored_iv, iv, 16);
    size_t new_iv_size = encode64(&stored_iv, 16); // Encode the stored key in Base64 format.

    FILE *file2 = fopen("./textfiles/iv.txt", "w");
    if (file2 == NULL){
        free(key_array);
        free(decoded_key_array);
        free(stored_iv);
        free(stored_key); // Free the allocated memory after use.
        return;
    }
    

    fwrite(stored_iv, 1, new_iv_size, file2);
    fclose(file2);

    free(key_array);
    free(decoded_key_array);
    free(stored_iv);
    free(stored_key); // Free the allocated memory after use.
}

// Function to encrypt a plaintext string using AES in CBC mode.
// This includes padding, block-wise encryption, and chaining with the IV.
int encrypt(char** buffer, unsigned char* key, unsigned char* iv) {
    const int block_size = 16; // AES block size.

    int num_blocks = ((int)strlen(*buffer) + block_size - 1) / block_size; // Calculate the number of blocks.

    unsigned char states[num_blocks][4][4]; // Array to hold the state matrices for each block.

    int x = 0;

    // Convert the plaintext into state matrices.
    for (int i = 0; i < num_blocks; i++) {
        for (int j = 0; j < 4; j++) {
            for (int y = 0; y < 4; y++) {
                if (x < (int)strlen(*buffer)) {
                    states[i][y][j] = (unsigned int)(*buffer)[x];
                } else {
                    states[i][y][j] = 0; // Pad with zeros if necessary.
                }
                x++;
            }
        }
    }

    cbc_init(&states[0], iv); // XOR the first block with the IV.

    unsigned char prev[4][4];
    memcpy(prev, states[0], sizeof(prev)); // Store the first block for chaining.

    AES_Encrypt(&states[0], key); // Encrypt the first block.

    // Encrypt the remaining blocks using CBC mode.
    for (int i=1; i < num_blocks; i++){
        cbc_main(&states[i], prev); // XOR the current block with the previous ciphertext block.
        AES_Encrypt(&states[i], key); // Encrypt the current block.
        memcpy(prev, states[i], sizeof(prev)); // Update the previous block.
    }

    // Flatten the state matrices back into a single array.
    unsigned char arr[x];
    x=0;
    for (int i = 0; i < num_blocks; i++) {
        for (int j = 0; j < 4; j++) {
            for (int y = 0; y < 4; y++) {
                arr[x] = states[i][y][j];
                x++;
            }
        }
    }

    // Copy the encrypted data back into the original string.
    for(int i=0; i<x; i++){
        (*buffer)[i] = arr[i];
    }
    (*buffer)[x] = '\0'; // Null-terminate the buffer.

    return x;
}



void cbc_main(unsigned char (*plaintext)[4][4], unsigned char prev[4][4]){
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            (*plaintext)[i][j] ^= prev[i][j];
        }
    }
}

void cbc_init(unsigned char (*plaintext)[4][4], unsigned char* iv) {
    int x = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            (*plaintext)[i][j] ^= iv[x];
            x++;
        }
    }
}

void write_pass(char* struct_user, char* struct_pass){
    int sizeOfStruct = 0;

    sizeOfStruct = strlen(struct_user) + strlen(struct_pass);

    char *storePass = (char*)malloc(sizeof(char) * sizeOfStruct*2);
    snprintf(storePass, sizeOfStruct*2, "%s:%s:", struct_user, struct_pass);

    const int key_size = 256; // AES-256 key size.
    unsigned char key[32];
    unsigned char iv[16];

    gen_key(key, key_size); // Generate a random encryption key.
    gen_iv(iv); // Generate a random initialization vector.
    getPadded(&storePass); // Pad the plaintext.

    int size = encrypt(&storePass, key, iv); // Encrypt Username and Password

    StoreKey(key); // Encrypt and store key used to encrypt Username and Password

    size_t new_size = encode64(&storePass, size); // Base64 encode encrypted Username and Password for storage

    FILE *file = fopen("./textfiles/password.txt", "w");
    if (file == NULL){
        free(storePass);
        return;
    }
    fwrite(storePass, new_size, 1, file);
    fclose(file);

    free(storePass);
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <username> <password>\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct passwords pass;
    pass.username = argv[1];
    pass.password = argv[2];

    write_pass(pass.username, pass.password);

    return 0;
}
