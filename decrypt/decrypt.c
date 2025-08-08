#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decode64.h"
#include "../encrypt/encode64.h"
#include "AES_Decrypt.h"

#include <direct.h>
#define DATA_DIR "textfiles"


unsigned char* decrypt(char *masterkey, char *key, char *iv, char *ciphertext, char *pass_iv,
            size_t masterkey_size, size_t key_size, size_t iv_size, size_t ciphertext_size, size_t pass_iv_size);
void cbc_init(unsigned char (*state)[4][4], unsigned char *key);
void cbc_init(unsigned char (*plaintext)[4][4], unsigned char* iv);
void cbc_main(unsigned char (*plaintext)[4][4], unsigned char prev[4][4]);

void perform_AES(unsigned char** ciphertext, size_t ciphertext_size, unsigned char* key, unsigned char *iv);

// #define MAINACTIVE;

void perform_AES(unsigned char** ciphertext, size_t ciphertext_size, unsigned char* key, unsigned char *iv){
    const int block_size = 16;
    int num_blocks = (ciphertext_size + block_size - 1) / block_size;

    unsigned char states[num_blocks][4][4];

    int x = 0;
    for (int i = 0; i < num_blocks; i++) {
        for (int y = 0; y < 4; y++) {
            for (int j = 0; j < 4; j++) {
                if (x < (int)ciphertext_size) {
                    states[i][j][y] = (*ciphertext)[x];
                } else {
                    states[i][j][y] = 0;
                }
                x++;
            }
        }
    }

    unsigned char prev[4][4];
    unsigned char temp_prev[4][4];
    memcpy(prev, states[0], sizeof(prev));
    AES_Decrypt(&states[0], key);
    cbc_init(&states[0], iv);

    for(int i = 1; i < num_blocks; i++){
        memcpy(temp_prev, states[i], sizeof(temp_prev));
        AES_Decrypt(&states[i], key);
        cbc_main(&states[i], prev);
        memcpy(prev, temp_prev, sizeof(temp_prev));
    }

    unsigned char* arr = (unsigned char*)malloc(num_blocks * block_size);
    if (arr == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return;
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
unsigned char* decrypt(char *masterkey, char *key, char *key_iv, char *ciphertext, char *pass_iv,
             size_t masterkey_size, size_t key_size, size_t iv_size, size_t ciphertext_size, size_t pass_iv_size) {
    // Only declare pointers, let decode_base64 allocate memory
    unsigned char *decoded_masterkey = NULL;
    unsigned char *decoded_key = NULL;
    unsigned char *decoded_key_iv = NULL;
    unsigned char *decoded_ciphertext = NULL;
    unsigned char *decoded_pass_iv = NULL;
    size_t decoded_masterkey_size, decoded_key_size, decoded_iv_size, decoded_ciphertext_size, decoded_pass_iv_size;

    decode_base64(masterkey, &decoded_masterkey, &decoded_masterkey_size);
    decode_base64(key, &decoded_key, &decoded_key_size);
    decode_base64(key_iv, &decoded_key_iv, &decoded_iv_size);
    decode_base64(ciphertext, &decoded_ciphertext, &decoded_ciphertext_size);
    decode_base64(pass_iv, &decoded_pass_iv, &decoded_pass_iv_size);

    // Decrypt the key using the master key and IV (if that's your design)
    // If not, skip this step and use decoded_key directly
    perform_AES(&decoded_key, decoded_key_size, decoded_masterkey, decoded_key_iv);

    unsigned char pad = decoded_key[ciphertext_size - 1];
    
    int remove_pad = 0;
    for (int i = decoded_key_size - 1; i >= 0; i--){
        if(decoded_key[i] == pad){
            remove_pad++;
        }
    }

    decoded_key_size -= remove_pad;
    decoded_key = (unsigned char*)realloc(decoded_key, decoded_key_size + 1);
    decoded_key[decoded_key_size] = '\0';

    // Decrypt the ciphertext using the key and IV
    perform_AES(&decoded_ciphertext, decoded_ciphertext_size, decoded_key, decoded_pass_iv);

    pad = decoded_ciphertext[decoded_ciphertext_size - 1];
    
    remove_pad = 0;
    for (int i = decoded_ciphertext_size - 1; i >= 0; i--){
        if(decoded_ciphertext[i] == pad){
            remove_pad++;
        }
    }

    decoded_ciphertext_size -= remove_pad;
    decoded_ciphertext = (unsigned char*)realloc(decoded_ciphertext, decoded_ciphertext_size + 1);
    decoded_ciphertext[decoded_ciphertext_size] = '\0';

    free(decoded_masterkey);
    free(decoded_key);
    free(decoded_key_iv);
    free(decoded_ciphertext);
    free(decoded_pass_iv);

    return decoded_ciphertext;
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

void cbc_main(unsigned char (*plaintext)[4][4], unsigned char prev[4][4]){
    for (int y = 0; y < 4; y++) {
        for (int j = 0; j < 4; j++) {
            (*plaintext)[j][y] ^= prev[j][y];
        }
    }
}

#ifdef MAINACTIVE
int main(int argc, char *argv[]) {
    if (argc != 11){
        fprintf(stderr, "Usage: %s <masterkey> <key> <keyiv> <ciphertext> <passiv> <msize> <ksize> <keyivsize> <csize> <passivsize>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int msize = atoi(argv[6]), ksize = atoi(argv[7]), ivsize = atoi(argv[8]), csize = atoi(argv[9]), passivsize = atoi(argv[10]);
    char MASTERKEY[msize + 1], KEY[ksize + 1], KEYIV[ivsize + 1], CIPHERTEXT[csize + 1], PASSIV[passivsize + 1];

    strncpy(MASTERKEY, argv[1], msize);
    MASTERKEY[msize] = '\0';
    strncpy(KEY, argv[2], ksize);
    KEY[ksize] = '\0';
    strncpy(KEYIV, argv[3], ivsize);
    KEYIV[ivsize] = '\0';
    strncpy(CIPHERTEXT, argv[4], csize);
    CIPHERTEXT[csize] = '\0';
    strncpy(PASSIV, argv[5], passivsize);
    PASSIV[passivsize] = '\0';

    printf("%s, %s, %s, %s\n", MASTERKEY, KEY, KEYIV, CIPHERTEXT);

    char *plaintext = decrypt(MASTERKEY, KEY, KEYIV, CIPHERTEXT, PASSIV, msize, ksize, ivsize, csize, passivsize);

    char output_path[256];
    snprintf(output_path, sizeof(output_path), "%s/output.txt", DATA_DIR);
    FILE *output = fopen(output_path, "w");
    if (output == NULL){
        free(MASTERKEY);
        free(KEY);
        free(CIPHERTEXT);
        free(PASSIV);
        free(KEYIV);
        perror("Error opening output.txt");
        return -1;
    }

    // Get the size of plaintext by calculating its length
    size_t plaintext_size = strlen((char*)plaintext);

    fwrite(plaintext, 1, plaintext_size, output);
    fclose(output);

    free(MASTERKEY);
    free(KEY);
    free(CIPHERTEXT);
    free(PASSIV);
    free(KEYIV);
    free(plaintext);

    return 0;
}
#endif
