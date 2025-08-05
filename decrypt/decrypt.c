#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decode64.h"
#include "../encrypt/encode64.h"

#include <openssl/rand.h>
#include <openssl/evp.h>

// #define MAINACTIVE;

void decrypt(char *masterkey, char *key, char *iv, char *ciphertext, size_t masterkey_size, size_t key_size, size_t iv_size, size_t ciphertext_size);

// Function to decrypt the password using the master key, key, IV, and ciphertext
// This function decodes the Base64 encoded strings, decrypts the ciphertext.
void decrypt(char *masterkey, char *key, char *iv, char *ciphertext, size_t masterkey_size, size_t key_size, size_t iv_size, size_t ciphertext_size) {
    printf("%s, %s, %s, %s\n", masterkey, key, iv, ciphertext);

    // Decode the Base64 encoded strings
    // Calculate the size of the decoded values
    size_t decoded_masterkey_size = (3 * masterkey_size) / 4 - 2, 
           decoded_key_size = (3 * key_size) / 4 - 2,
           decoded_iv_size = (3 * iv_size) / 4 - 2,
           decoded_ciphertext_size = (3 * ciphertext_size) / 4 - 2;

    // Allocate memory for the decoded values
    unsigned char *decoded_masterkey = (unsigned char *)malloc(decoded_masterkey_size);
    unsigned char *decoded_key = (unsigned char *)malloc(decoded_key_size);   
    unsigned char *decoded_iv = (unsigned char *)malloc(decoded_iv_size);
    unsigned char *decoded_ciphertext = (unsigned char *)malloc(decoded_ciphertext_size);

    // Decode the Base64 encoded strings
    decode_base64(masterkey, &decoded_masterkey, &decoded_masterkey_size);
    decode_base64(key, &decoded_key, &decoded_key_size);    
    decode_base64(iv, &decoded_iv, &decoded_iv_size);
    decode_base64(ciphertext, &decoded_ciphertext, &decoded_ciphertext_size);

    decoded_masterkey[decoded_masterkey_size] = '\0';
    decoded_key[decoded_key_size] = '\0';
    decoded_iv[decoded_iv_size] = '\0';
    decoded_ciphertext[decoded_ciphertext_size] = '\0';

    free(decoded_masterkey);
    free(decoded_key);
    free(decoded_iv);
    free(decoded_ciphertext);
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