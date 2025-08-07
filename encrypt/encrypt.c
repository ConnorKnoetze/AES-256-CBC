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
// #define USE_SEEDED_RANDOM

// Function to seed the OpenSSL random number generator for testing purposes.
void seed_random() {
    const unsigned char seed[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10}; // Constant seed for reproducibility.
    RAND_seed(seed, sizeof(seed));
}

#ifdef USE_SEEDED_RANDOM

// Function to generate a fixed initialization vector (IV) for testing purposes.
void gen_printable_iv(unsigned char* iv) {
    // 16 printable ASCII characters (example: digits and uppercase)
    const char printable_iv[17] = "1234ABCDEFGH5678";
    memcpy(iv, printable_iv, 16);
}

// Function to generate a fixed encryption key for testing purposes.
void gen_key(unsigned char* key, int key_size){
    // 32 printable ASCII characters (example: all uppercase letters and digits)
    const char printable_key[33] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";
    memcpy(key, printable_key, 32);
}

// Function to generate a fixed printable master key for testing purposes.
void gen_masterkey(unsigned char* masterkey) {
    // 32 printable ASCII characters (example: uppercase letters and lowercase letters)
    const char printable_masterkey[33] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
    memcpy(masterkey, printable_masterkey, 32);
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
void getPadded(char** buffer) {
    size_t orig_len = strlen(*buffer);
    int pad = orig_len % 16;
    if (pad == 0) {
        pad = 16;
    } else {
        pad = 16 - pad;
    }

    char *final_string = (char*)realloc(*buffer, orig_len + pad + 1);
    if (final_string == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    for (int i = 0; i < pad; i++) {
        final_string[orig_len + i] = (char)pad;
    }
    final_string[orig_len + pad] = '\0';

    *buffer = final_string;
}

// Function to store key used in instance to encrypt password.
// Using a Master key
void StoreKey(unsigned char* key) {
    unsigned char iv[17];
    gen_iv(iv);

    char* masterkey_array = (char*)malloc(45);

    FILE *file = fopen("./textfiles/masterkey.txt", "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    while (fgets(masterkey_array, 45, file) != NULL) {}
    fclose(file);

    size_t size = (3 * 45) / 4 - 2; // Size of decoded master key

    unsigned char *decoded_masterkey_array = (unsigned char *)malloc(size);
    if (decoded_masterkey_array == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        free(masterkey_array);
        return;
    }

    decode_base64(masterkey_array, &decoded_masterkey_array, &size);

    char* key_chars = (char*)malloc(33);
    if (key_chars == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    for (int i = 0; i < 32; i++) {
        key_chars[i] = (char)key[i];
    }
    key_chars[32] = '\0';

    getPadded(&key_chars);
    size_t padded_len = strlen(key_chars); 

    for (size_t i = 0; i < padded_len; i++) {
        printf("%02x", (unsigned char)key_chars[i]);
    }
    printf("\n");

    encrypt(&key_chars, decoded_masterkey_array, iv); 

    printf("Stored Key (Hex): ");
    for (size_t i = 0; i < padded_len; i++) {
        printf("%02x", (unsigned char)key_chars[i]);
    }
    printf("\n");

    int new_size = encode64(&key_chars, 48);

    printf("encrypted key (base64): ");
    printf("%s\n", key_chars);

    FILE *file1 = fopen("./textfiles/key.txt", "w");
    if (file1 == NULL) {
        free(masterkey_array);
        free(decoded_masterkey_array);
        free(key_chars);
        return;
    }

    fwrite(key_chars, 1, new_size, file1);
    free(key_chars);
    fclose(file1);

    char *stored_iv = (char*)malloc(16);
    if (stored_iv == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    memcpy(stored_iv, iv, 16);

    size_t new_iv_size = encode64(&stored_iv, 16); // Encode the stored key in Base64 format.
    printf("iv (base64): ");
    printf("%s\n", stored_iv);

    FILE *file2 = fopen("./textfiles/key_iv.txt", "w");
    if (file2 == NULL){
        free(masterkey_array);
        free(decoded_masterkey_array);
        free(stored_iv);
        free(key_chars); // Free the allocated memory after use.
        return;
    }
    

    fwrite(stored_iv, 1, new_iv_size, file2);
    fclose(file2);

    free(masterkey_array);
    free(stored_iv);
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
                    states[i][y][j] = (unsigned char)(*buffer)[x];
                } else {
                    states[i][y][j] = 0; // Pad with zeros if necessary.
                }
                x++;
            }
        }
    }

    cbc_init(&states[0], iv); // XOR the first block with the IV.
    AES_Encrypt(&states[0], key); // Encrypt the first block.

    unsigned char prev[4][4];
    memcpy(prev, states[0], sizeof(prev)); // Store the ciphertext of the first block for chaining.

    // Encrypt the remaining blocks using CBC mode.
    for (int i = 1; i < num_blocks; i++) {
        cbc_main(&states[i], prev); // XOR the current block with the previous ciphertext block.
        AES_Encrypt(&states[i], key); // Encrypt the current block.
        memcpy(prev, states[i], sizeof(prev)); // Update the previous block.
    }

    // Flatten the state matrices back into a single array.
    unsigned char* arr = (unsigned char*)malloc(num_blocks * block_size);
    if (arr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }

    x = 0;
    for (int i = 0; i < num_blocks; i++) {
        for (int y = 0; y < 4; y++) {
            for (int j = 0; j < 4; j++) {
                arr[x] = states[i][j][y];
                x++;
            }
        }
    }

    *buffer = (char*)realloc(*buffer, x + 1);
    if (*buffer == NULL) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(arr);
        return -1;
    }
    memcpy(*buffer, arr, x);
    (*buffer)[x] = '\0'; // Null-terminate the buffer.

    free(arr);

    return x;
}


void cbc_main(unsigned char (*plaintext)[4][4], unsigned char prev[4][4]){
    for (int y = 0; y < 4; y++) {
        for (int j = 0; j < 4; j++) {
            (*plaintext)[j][y] ^= prev[j][y];
        }
    }
}

void cbc_init(unsigned char (*plaintext)[4][4], unsigned char* iv) {
    int x = 0;
    for (int y = 0; y < 4; y++) {
        for (int j = 0; j < 4; j++) {
            (*plaintext)[j][y] ^= iv[x];
            x++;
        }
    }
}

void write_pass(char* struct_user, char* struct_pass){
    int sizeOfStruct = 0;

    sizeOfStruct = strlen(struct_user) + strlen(struct_pass);

    printf("%d\n",sizeOfStruct);

    char *storePass = (char*)malloc(sizeof(char) * sizeOfStruct*2);
    snprintf(storePass, sizeOfStruct*2, "%s:%s", struct_user, struct_pass);

    const int key_size = 256; // AES-256 key size.
    unsigned char key[32];

    gen_key(key, key_size); // Generate a random encryption key.

    #ifdef USE_SEEDED_RANDOM
    unsigned char iv[16];
    gen_printable_iv(iv); // Generate a random initialization vector
    #else
    unsigned char iv[17];
    gen_iv(iv);
    iv[16] = '\0';
    #endif
    getPadded(&storePass); // Pad the plaintext.


    int size = encrypt(&storePass, key, iv); // Encrypt Username and Password
    printf("Storepass encrypted (Hex): ");
    for (size_t i = 0; i < (size_t)size; i++) {
        printf("%02x", (unsigned char)storePass[i]);
    }
    printf("\n");
    size_t new_size = encode64(&storePass, size); // Base64 encode encrypted Username and Password for storage
    printf("Storepass encrypted (base64): ");
    printf("%s\n", storePass);

    StoreKey(key); // Encrypt and store key used to encrypt Username and Password

    FILE *passwordFile = fopen("./textfiles/password.txt", "w");
    if (passwordFile == NULL){
        free(storePass);
        return;
    }

    fwrite(storePass, new_size, 1, passwordFile);
    fclose(passwordFile);

    char *pass_iv = (char*)malloc(16);
    if (pass_iv == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }
    memcpy(pass_iv, iv, 16);

    size_t new_iv_size = encode64(&pass_iv, 16); // Encode the stored key in Base64 format.
    printf("iv (base64): ");
    printf("%s\n", pass_iv);

    FILE *ivFile = fopen("./textfiles/pass_iv.txt", "w");
    if (ivFile == NULL){
        free(storePass);
        return;
    }
    fwrite(pass_iv, 1, new_iv_size, ivFile);

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
