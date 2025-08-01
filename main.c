#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>


void cbc_init(unsigned char (*plaintext)[4][4], unsigned char* iv);
void cbc_main(unsigned char (*plaintext)[4][4], unsigned char prev[4][4]);
unsigned char gf_mul(unsigned char a, unsigned char b);

const unsigned char aes_sbox[256] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

struct passwords 
{
    char *username;
    char *password;
};

// Function to generate a random initialization vector (IV) using OpenSSL's RAND_bytes.
// The IV is critical for ensuring that the same plaintext encrypts to different ciphertexts.
void gen_iv(unsigned char* iv){
    if (RAND_bytes(iv, 16) != 1) {
        fprintf(stderr, "Error generating IV\n");
        exit(EXIT_FAILURE);
    }
}

// Function to generate a random encryption key of the specified size (in bits).
// Uses OpenSSL's RAND_bytes to ensure cryptographic randomness.
void gen_key(unsigned char* key, int key_size){
    int key_size_bytes = key_size / 8; // Convert key size from bits to bytes.
    if (RAND_bytes(key, key_size_bytes) != 1){
        fprintf(stderr, "Error generating random key\n");
        exit(EXIT_FAILURE);
    }
}

// Function to get user input for username and password.
void get_inp(char* struct_user, char* struct_pass) {
    printf("Please Enter a Username: \n");
    scanf("%255s", struct_user);

    printf("Please Enter a Password: \n");
    scanf("%255s", struct_pass);
}

// Function to apply the AES S-box substitution to the state matrix.
// This is a non-linear transformation that increases security by obscuring relationships between plaintext and ciphertext.
void SubBytes(unsigned char (*states)[4][4]){
    for (int j = 0; j < 4; j++) {
        for (int y = 0; y < 4; y++) {
            (*states)[j][y] = aes_sbox[(*states)[j][y]];
        }
    }
}

// Function to perform the ShiftRows step in AES.
// This step cyclically shifts rows of the state matrix to the left, introducing diffusion.
void ShiftRows(unsigned char (*state)[4][4]){
    unsigned char temp[4];

    // Shift the second row by 1 position.
    for (int i = 0; i < 4; i++) {
        temp[i] = (*state)[1][(i + 1) % 4];
    }
    for (int i = 0; i < 4; i++) {
        (*state)[1][i] = temp[i];
    }

    // Shift the third row by 2 positions.
    for (int i = 0; i < 4; i++) {
        temp[i] = (*state)[2][(i + 2) % 4];
    }
    for (int i = 0; i < 4; i++) {
        (*state)[2][i] = temp[i];
    }

    // Shift the fourth row by 3 positions.
    for (int i = 0; i < 4; i++) {
        temp[i] = (*state)[3][(i + 3) % 4];
    }
    for (int i = 0; i < 4; i++) {
        (*state)[3][i] = temp[i];
    }
}

// Function to perform the MixColumns step in AES.
// This step mixes the data within each column of the state matrix using Galois Field arithmetic.
void MixColumns(unsigned char (*state)[4][4]){
    const unsigned int mix_columns_matrix[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
    };

    unsigned int temp[4];

    for (int col = 0; col < 4; col++) { // Process each column
        for (int row = 0; row < 4; row++) {
            temp[row] = gf_mul(mix_columns_matrix[row][0], (*state)[0][col]) ^
                        gf_mul(mix_columns_matrix[row][1], (*state)[1][col]) ^
                        gf_mul(mix_columns_matrix[row][2], (*state)[2][col]) ^
                        gf_mul(mix_columns_matrix[row][3], (*state)[3][col]);
        }
        for (int row = 0; row < 4; row++) {
            (*state)[row][col] = temp[row];
        }
    }
}

// Function to expand a 256-bit key into 15 round keys for AES-256.
// This includes applying the Rcon constant and S-box substitution for key schedule generation.
void KeyExpansion256(unsigned char* key, unsigned char roundKeys[15][4][4]) {
    const unsigned char Rcon[14] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D};

    // Copy the original key into the first round key.
    for (int i = 0; i < 32; i++) {
        roundKeys[0][i / 4][i % 4] = key[i];
    }

    // Generate subsequent round keys.
    for (int round = 1; round <= 14; round++) {
        unsigned char temp[4];

        // Rotate and substitute the last column of the previous round key.
        for (int i = 0; i < 4; i++) {
            temp[i] = roundKeys[round - 1][i][7];
        }

        unsigned char t = temp[0];
        temp[0] = temp[1];
        temp[1] = temp[2];
        temp[2] = temp[3];
        temp[3] = t;

        for (int i = 0; i < 4; i++) {
            temp[i] = aes_sbox[temp[i]];
        }

        temp[0] ^= Rcon[round - 1];

        // Generate the first column of the current round key.
        for (int i = 0; i < 4; i++) {
            roundKeys[round][i][0] = roundKeys[round - 1][i][0] ^ temp[i];
        }

        // Generate the remaining columns of the current round key.
        for (int col = 1; col < 8; col++) {
            for (int i = 0; i < 4; i++) {
                roundKeys[round][i][col] = roundKeys[round - 1][i][col] ^ roundKeys[round][i][col - 1];
            }
        }
    }
}

// Function to XOR the state matrix with the round key.
// This is the AddRoundKey step in AES, which combines the key with the state.
void AddRoundKey(unsigned char (*state)[4][4], unsigned char (*roundKey)[4]){
    for (int i=0; i<4; i++){
        for (int j=0; j<4; j++){
            (*state)[i][j] ^= roundKey[i][j];
        }
    }
}

// Function to perform AES encryption on a single 16-byte block.
// This includes all AES rounds and the final AddRoundKey step.
void AES_Encrypt(unsigned char (*state)[4][4], unsigned char *key){

    unsigned char roundKeys[15][4][4];
    KeyExpansion256(key, roundKeys); // Generate round keys.

    // Initial round: Add the first round key.
    AddRoundKey(state, roundKeys[0]);

    // Main rounds: Apply SubBytes, ShiftRows, MixColumns, and AddRoundKey.
    for (int i=1; i < 14; i++){
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys[i]);
    }

    // Final round: Apply SubBytes, ShiftRows, and AddRoundKey (no MixColumns).
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys[14]);
}

// Function to pad the plaintext to a multiple of 16 bytes.
// Padding is necessary for AES, which operates on fixed-size blocks.
void getPadded(char** storePass) {
    int pad = strlen(*storePass) % 16;
    if (pad == 0) {
        pad = 16;
    } else {
        pad = 16 - pad;
    }

    // Allocate memory for the padding and append it to the plaintext.
    char *padding = (char*)malloc(pad + 1);
    for (int i = 0; i < pad; i++) {
        padding[i] = (char)(pad); // Use PKCS#7 padding scheme.
    }
    padding[pad] = '\0';

    char *final_string = (char*)realloc(*storePass, strlen(*storePass) + strlen(padding) + 1);
    strcat(final_string, padding);

    free(padding);

    *storePass = final_string;
}

// Function to encrypt a plaintext string using AES in CBC mode.
// This includes padding, block-wise encryption, and chaining with the IV.
void encrypt(char** storePass) {

    const int key_size = 256; // AES-256 key size.
    const int block_size = 16; // AES block size.

    unsigned char key[32];
    unsigned char iv[16];

    gen_key(key, key_size); // Generate a random encryption key.
    gen_iv(iv); // Generate a random initialization vector.
    getPadded(storePass); // Pad the plaintext.

    int num_blocks = ((int)strlen(*storePass) + block_size - 1) / block_size; // Calculate the number of blocks.

    unsigned char states[num_blocks][4][4]; // Array to hold the state matrices for each block.

    int x = 0;

    // Convert the plaintext into state matrices.
    for (int i = 0; i < num_blocks; i++) {
        for (int j = 0; j < 4; j++) {
            for (int y = 0; y < 4; y++) {
                if (x < (int)strlen(*storePass)) {
                    states[i][j][y] = (unsigned int)(*storePass)[x];
                } else {
                    states[i][j][y] = 0; // Pad with zeros if necessary.
                }
                x++;
            }
        }
    }

    cbc_init(&states[0], iv); // XOR the first block with the IV.

    unsigned char prev[4][4];
    memcpy(prev, states[0], sizeof(prev)); // Store the first block for chaining.

    AES_Encrypt(&states[0], key); // Encrypt the first block.

    // Encrypt the remaining blocks using CBC mode.
    for (int i=1; i < num_blocks; i++){
        cbc_main(&states[i], prev); // XOR the current block with the previous ciphertext block.
        AES_Encrypt(&states[i], key); // Encrypt the current block.
        memcpy(prev, states[i], sizeof(prev)); // Update the previous block.
    }

    // Flatten the state matrices back into a single array.
    unsigned char arr[x];
    x=0;
    for (int i = 0; i < num_blocks; i++) {
        for (int j = 0; j < 4; j++) {
            for (int y = 0; y < 4; y++) {
                arr[x] = states[i][j][y];
                x++;
            }
        }
    }

    // Copy the encrypted data back into the original string.
    for(int i=0; i<x; i++){
        (*storePass)[i] = arr[i];
    }
}

void cbc_main(unsigned char (*plaintext)[4][4], unsigned char prev[4][4]){
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            (*plaintext)[i][j] ^= prev[i][j];
        }
    }
}

void cbc_init(unsigned char (*plaintext)[4][4], unsigned char* iv) {
    int x = 0;
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            (*plaintext)[i][j] ^= iv[x];
            x++;
        }
    }
}

void write_pass(char* struct_user, char* struct_pass){
    FILE *file = fopen("./password.txt", "w");

    int sizeOfStruct = 0;

    sizeOfStruct = strlen(struct_user) + strlen(struct_pass);

    char *storePass = (char*)malloc(sizeof(char) * sizeOfStruct*2);
    snprintf(storePass, sizeOfStruct*2, "%s:%s:", struct_user, struct_pass);

    encrypt(&storePass);

    fwrite(storePass, sizeOfStruct*2, 1, file);
    fclose(file);

    free(storePass);
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

// Function to perform Galois Field multiplication of two bytes.
// This is used in the MixColumns step of AES to mix data within columns.
unsigned char gf_mul(unsigned char a, unsigned char b) {
    unsigned char result = 0;
    while (b) {
        if (b & 1) {
            result ^= a; // Add a to the result if the lowest bit of b is set.
        }
        unsigned char high_bit_set = a & 0x80; // Check if the highest bit of a is set.
        a <<= 1; // Multiply a by x (shift left).
        if (high_bit_set) {
            a ^= 0x1b; // Perform modulo reduction with the AES irreducible polynomial.
        }
        b >>= 1; // Divide b by x (shift right).
    }
    return result;
}

int main() {
    struct passwords pass;
    pass.password = (char*)malloc(256 * sizeof(char));
    pass.username = (char*)malloc(256 * sizeof(char));

    get_inp(pass.username, pass.password);

    write_pass(pass.username, pass.password);

    // read_pass();

    free(pass.password);
    free(pass.username);
    
    return 0;
}
