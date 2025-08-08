
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define DATA_DIR "textfiles"

#include "decrypt.c"

// Helper function to build file paths
void build_path(char *dest, size_t size, const char *filename) {
    snprintf(dest, size, "%s/%s", DATA_DIR, filename);
}


int main(){
    char path[256];
    FILE *masterkeyFile, *keyFile, *key_ivFile, *ciphertextFile, *pass_ivFile;

    build_path(path, sizeof(path), "masterkey.txt");
    masterkeyFile = fopen(path, "r");
    if (masterkeyFile == NULL) {
        perror("Error opening masterkey.txt");
        return -1;
    }
    build_path(path, sizeof(path), "key.txt");
    keyFile = fopen(path, "r");
    if (keyFile == NULL) {
        perror("Error opening key.txt");
        return -1;
    }
    build_path(path, sizeof(path), "key_iv.txt");
    key_ivFile = fopen(path, "r");
    if (key_ivFile == NULL) {
        perror("Error opening key_iv.txt");
        return -1;
    }
    build_path(path, sizeof(path), "password.txt");
    ciphertextFile = fopen(path, "r");
    if (ciphertextFile == NULL) {
        perror("Error opening password.txt");
        return -1;
    }
    build_path(path, sizeof(path), "pass_iv.txt");
    pass_ivFile = fopen(path, "r");
    if (pass_ivFile == NULL) {
        perror("Error opening pass_iv.txt");
        return -1;
    }

    fseek(masterkeyFile, 0, SEEK_END);
    long masterkey_size = ftell(masterkeyFile)+ 1;
    rewind(masterkeyFile);

    fseek(keyFile, 0, SEEK_END);
    long key_size = ftell(keyFile)+ 1;
    rewind(keyFile);

    fseek(key_ivFile, 0, SEEK_END);
    long iv_size = ftell(key_ivFile) + 1;
    rewind(key_ivFile);

    fseek(ciphertextFile, 0, SEEK_END);
    long ciphertext_size = ftell(ciphertextFile)+ 1;
    rewind(ciphertextFile);

    fseek(pass_ivFile, 0, SEEK_END);
    long pass_iv_size = ftell(pass_ivFile)+ 1;
    rewind(pass_ivFile);

    char *masterkey = (char *)malloc(masterkey_size);
    char *key = (char *)malloc(key_size);
    char *key_iv = (char *)malloc(iv_size);
    char *ciphertext = (char *)malloc(ciphertext_size);
    char *pass_iv = (char *)malloc(pass_iv_size);

    while(fgets(masterkey, masterkey_size, masterkeyFile)){};
    while(fgets(key, key_size, keyFile)){};
    while(fgets(key_iv, iv_size, key_ivFile)){};
    while(fgets(ciphertext, ciphertext_size, ciphertextFile)){};
    while(fgets(pass_iv, pass_iv_size, pass_ivFile)){};

    printf(" %s %s %s %s %s %d %d %d %d %d\n", masterkey, key, key_iv, ciphertext, pass_iv, masterkey_size, key_size, iv_size, ciphertext_size, pass_iv_size);
    unsigned char* plaintext = decrypt(masterkey, key, key_iv, ciphertext, pass_iv,masterkey_size, key_size, iv_size, ciphertext_size, pass_iv_size);


    char output_path[256];
    build_path(output_path, sizeof(output_path), "output.txt");
    FILE *output = fopen(output_path, "w");
    if (output == NULL){
        free(masterkey);
        free(key);  
        free(pass_iv);
        free(ciphertext);
        free(key_iv);
        perror("Error opening output.txt");
        return -1;
    }

    // Get the size of plaintext by calculating its length
    size_t plaintext_size = strlen((char*)plaintext);

    fwrite(plaintext, 1, plaintext_size, output);

    free(masterkey);
    free(key);  
    free(pass_iv);
    free(ciphertext);
    free(key_iv);

    printf("%s\n", plaintext);

    return 1;
}