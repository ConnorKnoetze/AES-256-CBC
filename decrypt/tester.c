#include <stdio.h>
#include <stdlib.h>

#include "decrypt.c"


int main(){
    FILE *file0 = fopen("./textfiles/masterkey.txt", "r");
    if (file0 == NULL) {
        perror("Error opening file");
        return -1;
    }
    FILE *file1 = fopen("./textfiles/key.txt", "r");
    if (file1 == NULL) {
        perror("Error opening file");
        return -1;
    }
    FILE *file2 = fopen("./textfiles/iv.txt", "r");
    if (file2 == NULL) {
        perror("Error opening file");
        return -1;
    }
    FILE *file3 = fopen("./textfiles/password.txt", "r");
    if (file3 == NULL) {
        perror("Error opening file");
        return -1;
    }

    fseek(file0, 0, SEEK_END);
    long masterkey_size = ftell(file0)+ 1;
    rewind(file0);

    fseek(file1, 0, SEEK_END);
    long key_size = ftell(file1)+ 1;
    rewind(file1);

    fseek(file2, 0, SEEK_END);
    long iv_size = ftell(file2) + 1;
    rewind(file2);

    fseek(file3, 0, SEEK_END);
    long ciphertext_size = ftell(file3)+ 1;
    rewind(file3);

    char *masterkey = (char *)malloc(masterkey_size);
    char *key = (char *)malloc(key_size);
    char *iv = (char *)malloc(iv_size);
    char *ciphertext = (char *)malloc(ciphertext_size);

    while(fgets(masterkey, masterkey_size, file0)){};
    while(fgets(key, key_size, file1)){};
    while(fgets(iv, iv_size, file2)){};
    while(fgets(ciphertext, ciphertext_size, file3)){};

    decrypt(masterkey, key, iv, ciphertext, masterkey_size, key_size, iv_size, ciphertext_size);

    free(masterkey);
    free(key);  
    free(iv);
    free(ciphertext);

    return 1;
}