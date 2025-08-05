#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decode64.h"

#include <openssl/rand.h>
#include <openssl/evp.h>

// #define MAINACTIVE;

void read_pass(char *input){
    FILE *file = fopen("./password.txt", "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    while (fgets(input, 2048, file) != NULL) {}
    fclose(file);
}

int decrypt(char *masterkey, char *key, char *iv, char *ciphertext, size_t masterkey_size, size_t key_size, size_t iv_size, size_t ciphertext_size) {
    printf("%s, %s, %s, %s\n", masterkey, key, iv, ciphertext);
}

#ifdef MAINACTIVE
int main(int argc, char *argv[]) {
    if (argc != 9){
        fprintf(stderr, "Usage: %s <masterkey> <key> <iv> <ciphertext>\n", argv[0]);
        return EXIT_FAILURE;
    }

    int msize=(int)argv[5], ksize=(int)argv[6], ivsize=(int)argv[7], csize=(int)argv[8];
    char MASTERKEY[msize], KEY[ksize], IV[ivsize], CIPHERTEXT[csize];

    printf("%s, %s, %s, %s\n", MASTERKEY, KEY, IV, CIPHERTEXT);

}
#endif