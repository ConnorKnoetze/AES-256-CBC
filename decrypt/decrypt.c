#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decode64.h"
#include "../encrypt/encode64.h"
#include "AES_Decrypt.h"

#include <openssl/rand.h>
#include <openssl/evp.h>

// #define MAINACTIVE;

void decrypt(char *masterkey, char *key, char *iv, char *ciphertext, size_t masterkey_size, size_t key_size, size_t iv_size, size_t ciphertext_size);
void cbc_init(unsigned char (*state)[4][4], unsigned char *key);
void cbc_init(unsigned char (*plaintext)[4][4], unsigned char* iv);
void cbc_main(unsigned char (*plaintext)[4][4], unsigned char prev[4][4]);

void perform_AES(unsigned char** ciphertext, size_t ciphertext_size, unsigned char* key, unsigned char *iv);

void perform_AES(unsigned char** ciphertext, size_t ciphertext_size, unsigned char* key, unsigned char *iv){
    const int block_size = 16;
    int num_blocks = (ciphertext_size + block_size - 1) / block_size;

    unsigned char states[num_blocks][4][4];

    int x = 0;
    for (int i = 0; i < num_blocks; i++) {
        for (int j = 0; j < 4; j++) {
            for (int y = 0; y < 4; y++) {
                if (x < (int)ciphertext_size) {
                    states[i][y][j] = (*ciphertext)[x];
                } else {
                    states[i][y][j] = 0;
                }
                x++;
            }
        }
    }

    unsigned char prev[4][4];
    AES_Decrypt(&states[0], key);
    cbc_init(&states[0], iv);
    memcpy(prev, states[0], sizeof(prev));

    for(int i = 1; i < num_blocks; i++){
        AES_Decrypt(&states[i], key);
        cbc_main(&states[i], prev);
        memcpy(prev, states[i], sizeof(prev));
    }

    unsigned char* arr = (unsigned char*)malloc(num_blocks * block_size);
    if (arr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
    }

    x = 0;
    for (int i = 0; i < num_blocks; i++) {
        for (int j = 0; j < 4; j++) {
            for (int y = 0; y < 4; y++) {
                arr[x] = states[i][y][j];
                x++;
            }
        }
    }

    (*ciphertext) = (unsigned char*)realloc(*ciphertext, x + 1);
    if ((*ciphertext) == NULL) {
        fprintf(stderr, "Memory reallocation failed\n");
        free(arr);
        return;
    }
    memcpy((*ciphertext), arr, x);
    (*ciphertext)[x] = '\0';

    free(arr);
}

// Function to decrypt the password using the master key, key, IV, and ciphertext
// This function decodes the Base64 encoded strings, decrypts the ciphertext.
void decrypt(char *masterkey, char *key, char *iv, char *ciphertext,
             size_t masterkey_size, size_t key_size, size_t iv_size, size_t ciphertext_size) {
    // Only declare pointers, let decode_base64 allocate memory
    unsigned char *decoded_masterkey = NULL;
    unsigned char *decoded_key = NULL;
    unsigned char *decoded_iv = NULL;
    unsigned char *decoded_ciphertext = NULL;
    size_t decoded_masterkey_size, decoded_key_size, decoded_iv_size, decoded_ciphertext_size;

    decode_base64(masterkey, &decoded_masterkey, &decoded_masterkey_size);
    decode_base64(key, &decoded_key, &decoded_key_size);
    decode_base64(iv, &decoded_iv, &decoded_iv_size);
    decode_base64(ciphertext, &decoded_ciphertext, &decoded_ciphertext_size);

    // Decrypt the key using the master key and IV (if that's your design)
    // If not, skip this step and use decoded_key directly
    perform_AES(&decoded_key, decoded_key_size, decoded_masterkey, decoded_iv);

    // Remove PKCS#7 padding
    size_t plaintext_len = decoded_key_size;
    unsigned char pad = decoded_key[plaintext_len - 1];
    if (pad > 0 && pad <= 16) {
        plaintext_len -= pad;
    }

    // Print as string (if text) or as hex
    printf("Decrypted: \n");
    for (size_t i = 0; i < decoded_key_size; i++) {
        printf("%c\n", decoded_key[i]);
    }
    printf("\n");
    printf("Decrypted (hex): ");
    for (size_t i = 0; i < decoded_key_size; i++) {
        printf("%02x ", decoded_key[i]);
    }
    printf("\n");


    // Decrypt the ciphertext using the key and IV
    perform_AES(&decoded_ciphertext, decoded_ciphertext_size, decoded_key, decoded_iv);


    free(decoded_masterkey);
    free(decoded_key);
    free(decoded_iv);
    free(decoded_ciphertext);
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

void cbc_main(unsigned char (*plaintext)[4][4], unsigned char prev[4][4]){
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            (*plaintext)[i][j] ^= prev[i][j];
        }
    }
}

#ifdef MAINACTIVE

int main(int argc, char *argv[]) {
    if (argc != 9){
        fprintf(stderr, "Usage: %s <masterkey> <key> <iv> <ciphertext> <msize> <ksize> <ivsize> <csize>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int msize=(int)argv[5], ksize=(int)argv[6], ivsize=(int)argv[7], csize=(int)argv[8];
    char MASTERKEY[msize], KEY[ksize], IV[ivsize], CIPHERTEXT[csize];

    strncpy(MASTERKEY, argv[1], msize);
    strncpy(KEY, argv[2], ksize);
    strncpy(IV, argv[3], ivsize);
    strncpy(CIPHERTEXT, argv[4], csize);

    printf("%s, %s, %s, %s\n", MASTERKEY, KEY, IV, CIPHERTEXT);

    decrypt(MASTERKEY, KEY, IV, CIPHERTEXT, msize, ksize, ivsize, csize);

}
#endif