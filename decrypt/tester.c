#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decrypt.h"


int main(){
    FILE *file0, *file1, *file2, *file3;

    file0 = fopen("./textfiles/masterkey.txt", "r");
    if (file0 == NULL) {
        perror("Error opening file");
        return -1;
    }
    file1 = fopen("./textfiles/key.txt", "r");
    if (file1 == NULL) {
        perror("Error opening file");
        return -1;
    }
    file2 = fopen("./textfiles/iv.txt", "r");
    if (file2 == NULL) {
        perror("Error opening file");
        return -1;
    }
    file3 = fopen("./textfiles/password.txt", "r");
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

    char masterkey[masterkey_size], key[key_size], iv[iv_size], ciphertext[ciphertext_size];

    while(fgets(masterkey, masterkey_size, file0)){};
    while(fgets(key, key_size, file1)){};
    while(fgets(iv, iv_size, file2)){};
    while(fgets(ciphertext, ciphertext_size, file3)){};

    masterkey[masterkey_size] = '\0',
    key[key_size] = '\0',
    iv[iv_size] = '\0',
    ciphertext[ciphertext_size] = '\0';

    decrypt(masterkey, key, iv, ciphertext, masterkey_size, key_size, iv_size, ciphertext_size);

    return 1;
}