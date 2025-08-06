#include <stdio.h>
#include <stdlib.h>
#include <string.h>


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

// Function to apply the AES S-box substitution to the state matrix.
// This is a non-linear transformation that increases security by obscuring relationships between plaintext and ciphertext.
void SubBytes(unsigned char (*state)[4][4]){
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            (*state)[row][col] = aes_sbox[(*state)[row][col]];
        }
    }
}


// Function to perform the ShiftRows step in AES.
// This step cyclically shifts rows of the state matrix to the left, introducing diffusion.
void ShiftRows(unsigned char (*state)[4][4]){
    unsigned char temp[4];

    // Row 1: shift left by 1
    for (int col = 0; col < 4; col++) {
        temp[col] = (*state)[1][(col + 1) % 4];
    }
    for (int col = 0; col < 4; col++) {
        (*state)[1][col] = temp[col];
    }

    // Row 2: shift left by 2
    for (int col = 0; col < 4; col++) {
        temp[col] = (*state)[2][(col + 2) % 4];
    }
    for (int col = 0; col < 4; col++) {
        (*state)[2][col] = temp[col];
    }

    // Row 3: shift left by 3
    for (int col = 0; col < 4; col++) {
        temp[col] = (*state)[3][(col + 3) % 4];
    }
    for (int col = 0; col < 4; col++) {
        (*state)[3][col] = temp[col];
    }
}


// Function to perform the MixColumns step in AES.
void MixColumns(unsigned char (*state)[4][4]) {
    for (int c = 0; c < 4; c++) {
        unsigned char a0 = (*state)[0][c];
        unsigned char a1 = (*state)[1][c];
        unsigned char a2 = (*state)[2][c];
        unsigned char a3 = (*state)[3][c];
        (*state)[0][c] = gf_mul(0x02, a0) ^ gf_mul(0x03, a1) ^ a2 ^ a3;
        (*state)[1][c] = a0 ^ gf_mul(0x02, a1) ^ gf_mul(0x03, a2) ^ a3;
        (*state)[2][c] = a0 ^ a1 ^ gf_mul(0x02, a2) ^ gf_mul(0x03, a3);
        (*state)[3][c] = gf_mul(0x03, a0) ^ a1 ^ a2 ^ gf_mul(0x02, a3);
    }
}


// Function to expand a 256-bit key into 15 round keys for AES-256.
void KeyExpansion256(const unsigned char* key, unsigned char roundKeys[15][4][4]) {
    unsigned char expandedKey[240]; // 60 words * 4 bytes
    const unsigned char Rcon[15] = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,0x6C,0xD8,0xAB,0x4D,0x9A};
    int i, j;
    // Copy the original key (32 bytes)
    for (i = 0; i < 32; i++) {
        expandedKey[i] = key[i];
    }
    int bytesGenerated = 32;
    int rconIter = 0;
    unsigned char temp[4];
    while (bytesGenerated < 240) {
        for (j = 0; j < 4; j++) {
            temp[j] = expandedKey[bytesGenerated - 4 + j];
        }
        if (bytesGenerated % 32 == 0) {
            // Rotate
            unsigned char t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // S-box
            for (j = 0; j < 4; j++) {
                temp[j] = aes_sbox[temp[j]];
            }
            // Rcon
            temp[0] ^= Rcon[rconIter++];
        } else if (bytesGenerated % 32 == 16) {
            // S-box only
            for (j = 0; j < 4; j++) {
                temp[j] = aes_sbox[temp[j]];
            }
        }
        for (j = 0; j < 4; j++) {
            expandedKey[bytesGenerated] = expandedKey[bytesGenerated - 32] ^ temp[j];
            bytesGenerated++;
        }
    }
    // Copy expandedKey into roundKeys (15 round keys, each 16 bytes)
    // User's original style, but with the bug fix: column-major order
    for (i = 0; i < 15; i++) {
        for (j = 0; j < 16; j++) {
            roundKeys[i][j % 4][j / 4] = expandedKey[i * 16 + j];
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