#include <stdio.h>
#include <stdlib.h>
#include <direct.h> // For _mkdir on Windows
#define DATA_DIR "textfiles"

#include "decrypt.c"


int main(){
    FILE *masterkeyFile = fopen("./AES/textfiles/masterkey.txt", "r");
    if (masterkeyFile == NULL) {
        perror("Error opening file");
        return -1;
    }
    FILE *keyFile = fopen("./AES/textfiles/key.txt", "r");
    if (keyFile == NULL) {
        perror("Error opening file");
        return -1;
    }
    FILE *key_ivFile = fopen("./AES/textfiles/key_iv.txt", "r");
    if (key_ivFile == NULL) {
        perror("Error opening file");
        return -1;
    }
    FILE *ciphertextFile = fopen("./AES/textfiles/password.txt", "r");
    if (ciphertextFile == NULL) {
        perror("Error opening file");
        return -1;
    }
    FILE *pass_ivFile = fopen("./AES/textfiles/pass_iv.txt", "r");
    if (pass_ivFile == NULL) {
        perror("Error opening file");
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


    unsigned char* plaintext = decrypt(masterkey, key, key_iv, ciphertext, pass_iv,masterkey_size, key_size, iv_size, ciphertext_size, pass_iv_size);

    char output_path[128];
    snprintf(output_path, sizeof(output_path), "%s/output.txt", DATA_DIR);
    FILE *output = fopen(output_path, "w");
    if (output == NULL){
        free(masterkey);
        free(key);  
        free(pass_iv);
        free(ciphertext);
        free(key_iv);
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