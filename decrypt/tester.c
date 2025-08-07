#include <stdio.h>
#include <stdlib.h>

#include "decrypt.c"


int main(){
    FILE *masterkeyFile = fopen("./textfiles/masterkey.txt", "r");
    if (masterkeyFile == NULL) {
        perror("Error opening file");
        return -1;
    }
    FILE *keyFile = fopen("./textfiles/key.txt", "r");
    if (keyFile == NULL) {
        perror("Error opening file");
        return -1;
    }
    FILE *ivFile = fopen("./textfiles/iv.txt", "r");
    if (ivFile == NULL) {
        perror("Error opening file");
        return -1;
    }
    FILE *ciphertextFile = fopen("./textfiles/password.txt", "r");
    if (ciphertextFile == NULL) {
        perror("Error opening file");
        return -1;
    }

    fseek(masterkeyFile, 0, SEEK_END);
    long masterkey_size = ftell(masterkeyFile)+ 1;
    rewind(masterkeyFile);

    fseek(keyFile, 0, SEEK_END);
    long key_size = ftell(keyFile)+ 1;
    rewind(keyFile);

    fseek(ivFile, 0, SEEK_END);
    long iv_size = ftell(ivFile) + 1;
    rewind(ivFile);

    fseek(ciphertextFile, 0, SEEK_END);
    long ciphertext_size = ftell(ciphertextFile)+ 1;
    rewind(ciphertextFile);

    char *masterkey = (char *)malloc(masterkey_size);
    char *key = (char *)malloc(key_size);
    char *iv = (char *)malloc(iv_size);
    char *ciphertext = (char *)malloc(ciphertext_size);

    while(fgets(masterkey, masterkey_size, masterkeyFile)){};
    while(fgets(key, key_size, keyFile)){};
    while(fgets(iv, iv_size, ivFile)){};
    while(fgets(ciphertext, ciphertext_size, ciphertextFile)){};

    unsigned char* plaintext = decrypt(masterkey, key, iv, ciphertext, masterkey_size, key_size, iv_size, ciphertext_size);

    printf("%s", plaintext);

    free(masterkey);
    free(key);  
    free(iv);
    free(ciphertext);

    return 1;
}