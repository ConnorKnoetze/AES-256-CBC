#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decode64.h"
#include "../encrypt/encode64.h"
#include "AES_Decrypt.h"

#include <openssl/rand.h>
#include <openssl/evp.h>

unsigned char* decrypt(char *masterkey, char *key, char *iv, char *ciphertext, char *pass_iv,
            size_t masterkey_size, size_t key_size, size_t iv_size, size_t ciphertext_size, size_t pass_iv_size);
void cbc_init(unsigned char (*state)[4][4], unsigned char *key);
void cbc_init(unsigned char (*plaintext)[4][4], unsigned char* iv);
void cbc_main(unsigned char (*plaintext)[4][4], unsigned char prev[4][4]);

void perform_AES(unsigned char** ciphertext, size_t ciphertext_size, unsigned char* key, unsigned char *iv);

// #define MAINACTIVE;
// #define MAIN2ACTIVE;
#ifdef MAINACTIVE
void test_perform_AES() {
    // Provided masterkey (ASCII): "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
    unsigned char masterkey[32] = {
        'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P',
        'Q','R','S','T','U','V','W','X','Y','Z','a','b','c','d','e','f'
    };
    // Example IV: "1234ABCDEFGH5678"
    unsigned char iv[16] = {
        '1','2','3','4','A','B','C','D','E','F','G','H','5','6','7','8'
    };
    // Provided ciphertext (hex) for CBC mode test
    unsigned char ciphertext[48] = {
        0xc7,0x8b,0xb7,0x0a,0xd6,0x34,0x19,0xf0,
        0xa7,0xa9,0xc0,0xf8,0x5f,0x4a,0x11,0xdb,
        0x85,0x47,0x4c,0x50,0xee,0x4e,0x43,0x37,
        0x4c,0xad,0x6b,0x0e,0x01,0xa5,0xa5,0x72,
        0x48,0x36,0xd3,0x4e,0xc3,0xcb,0xc1,0x0f,
        0xbf,0x44,0xd9,0xa8,0xfd,0x01,0xaa,0x1a
    };
    size_t ciphertext_size = 48;

    unsigned char* ciphertext_ptr = (unsigned char*)malloc(ciphertext_size);
    memcpy(ciphertext_ptr, ciphertext, ciphertext_size);

    printf("Test vector: Decrypting ciphertext with perform_AES...\n");
    perform_AES(&ciphertext_ptr, ciphertext_size, masterkey, iv);

    printf("Decrypted output (hex):\n");
    for (size_t i = 0; i < ciphertext_size; i++) {
        printf("%02x", ciphertext_ptr[i]);
    }
    printf("\n");

    printf("Decrypted output (ASCII):\n");
    for (size_t i = 0; i < ciphertext_size; i++) {
        if (ciphertext_ptr[i] >= 32 && ciphertext_ptr[i] <= 126)
            printf("%c", ciphertext_ptr[i]);
        else
            printf(".");
    }
    printf("\n");

    unsigned char pad = ciphertext_ptr[ciphertext_size - 1];
    
    int remove_pad = 0;
    for (int i = ciphertext_size - 1; i >= 0; i--){
        if(ciphertext_ptr[i] == pad){
            remove_pad++;
        }
    }

    ciphertext_size -= remove_pad;
    ciphertext_ptr = (unsigned char*)realloc(ciphertext_ptr, ciphertext_size + 1);
    ciphertext_ptr[ciphertext_size] = '\0';

    printf("%s", ciphertext_ptr);

    free(ciphertext_ptr);
}
#endif

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
#include <stdio.h>
int main() {
    test_perform_AES();
    return 0;
}
#endif

#ifdef MAIN2ACTIVE
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
