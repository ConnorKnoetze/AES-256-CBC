#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to perform Base64 encoding
int encode64(char** buffer, int size){
    const char base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int output_size = ((size + 2) / 3) * 4; // The size of the new output array

    char temp[output_size]; // Temporary array to store string while building

    int index = 0;
    // Increment over string 3 characters at a time
    for (int i = 0; i < size; i += 3) {
        // Isolate the three characters bitwise
        unsigned int b1 = (i < size) ? (unsigned char)(*buffer)[i] : 0;
        unsigned int b2 = (i + 1 < size) ? (unsigned char)(*buffer)[i + 1] : 0;
        unsigned int b3 = (i + 2 < size) ? (unsigned char)(*buffer)[i + 2] : 0;

        // Merge the characters in one buffer
        unsigned int bitBuffer = (b1 << 16) | (b2 << 8) | b3;

        // Take the buffer and split it in 4 pieces;
        // Then use the pieces to index into the base64_alphabet
        // Then assign that character to the temporary array
        temp[index++] = base64_alphabet[(bitBuffer >> 18) & 0x3F];
        temp[index++] = base64_alphabet[(bitBuffer >> 12) & 0x3F];
        temp[index++] = (i + 1 < size) ? base64_alphabet[(bitBuffer >> 6) & 0x3F] : '=';
        temp[index++] = (i + 2 < size) ? base64_alphabet[bitBuffer & 0x3F] : '=';
    } 
    *buffer = (char*)realloc(*buffer, output_size + 1); // Allocate space for null terminator.
    if (*buffer == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(*buffer, temp, output_size);
    (*buffer)[output_size] = '\0'; // Null-terminate the string.
    return output_size; // Return the size of the new string.
}