#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "decode64.h"

#include <openssl/rand.h>
#include <openssl/evp.h>


void decrypt(unsigned int *input){

}

void read_pass(char *input){
    FILE *file = fopen("./password.txt", "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    while (fgets(input, 2048, file) != NULL) {}
    fclose(file);
}

int main(){
    char inputBuffer[2048];
    read_pass(inputBuffer);
    int index = 0;

    while (inputBuffer[index] != '\0'){
        index++;
    }

    unsigned char input[index];
    index = 0;
    
    while (inputBuffer[index] != '\0'){
        input[index] = inputBuffer[index];
        index++;
    }

    decrypt(input);

}