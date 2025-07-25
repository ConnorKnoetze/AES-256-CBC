#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct passwords 
{
    char *username;
    char *password;
};

void get_inp(char* struct_user, char* struct_pass) {
    printf("Please Enter a Username: \n");
    scanf("%255s", struct_user);

    printf("Please Enter a Password: \n");
    scanf("%255s", struct_pass);
}

void write_pass(char* struct_user, char* struct_pass){
    FILE *file = fopen("./password.txt", "w");

    int sizeOfStruct = 0;

    sizeOfStruct = strlen(struct_user) + strlen(struct_pass);

    char *storePass = (char*)malloc(sizeof(char) * sizeOfStruct*2);
    snprintf(storePass, sizeOfStruct*2, "%s : %s\n", struct_user, struct_pass);

    fwrite(storePass, sizeOfStruct*2, 1, file);
    fclose(file);
}

void read_pass(){
    FILE *file = fopen("./password.txt", "r");
    if (file == NULL) {
        perror("Error opening file");
        return;
    }

    char readBuffer[512];

    while (fgets(readBuffer, sizeof(readBuffer), file) != NULL) {
        printf("%s", readBuffer);
    }
    fclose(file);
}

int main() {
    struct passwords pass;
    pass.password = (char*)malloc(256 * sizeof(char));
    pass.username = (char*)malloc(256 * sizeof(char));

    get_inp(pass.username, pass.password);
    write_pass(pass.username, pass.password);

    read_pass();

    free(pass.password);
    free(pass.username);
    
    return 0;
}
