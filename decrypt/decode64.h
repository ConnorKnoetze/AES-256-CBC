#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// Base64 decoding table
static const unsigned char base64_table[256] = {
    // 0-255
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 0-15
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 16-31
    255,255,255,255,255,255,255,255,255,255,255,62, 255,255,255,63,  // 32-47 (+,/)
    52,53,54,55,56,57,58,59,60,61,255,255,255,255,255,255,           // 48-63 (0-9)
    255, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,                // 64-79 (A-O)
    15,16,17,18,19,20,21,22,23,24,25,255,255,255,255,255,            // 80-95 (P-Z)
    255,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,                // 96-111 (a-o)
    41,42,43,44,45,46,47,48,49,50,51,255,255,255,255,255,            // 112-127 (p-z)
    // 128-255: all invalid
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 128-143
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 144-159
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 160-175
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 176-191
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 192-207
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 208-223
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255, // 224-239
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255  // 240-255
};

void decode_base64(const char *input, unsigned char **output, size_t *output_len);

void decode_base64(const char *input, unsigned char **output, size_t *output_len) {
    size_t input_len = strlen(input);
    size_t padding = 0;

    // Count padding characters ('=')
    if (input_len >= 2 && input[input_len - 1] == '=')
        padding++;
    if (input_len >= 2 && input[input_len - 2] == '=')
        padding++;

    // Calculate output length
    *output_len = (input_len / 4) * 3 - padding;
    *output = (unsigned char *)malloc(*output_len);
    if (*output == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(EXIT_FAILURE);
    }

    size_t j = 0;
    for (size_t i = 0; i < input_len; i += 4) {
        unsigned int sextet_a = input[i] == '=' ? 0 & i++ : base64_table[(unsigned char)input[i]];
        unsigned int sextet_b = input[i + 1] == '=' ? 0 & i++ : base64_table[(unsigned char)input[i + 1]];
        unsigned int sextet_c = input[i + 2] == '=' ? 0 & i++ : base64_table[(unsigned char)input[i + 2]];
        unsigned int sextet_d = input[i + 3] == '=' ? 0 & i++ : base64_table[(unsigned char)input[i + 3]];

        unsigned int triple = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

        if (j < *output_len) (*output)[j++] = (triple >> 16) & 0xFF;
        if (j < *output_len) (*output)[j++] = (triple >> 8) & 0xFF;
        if (j < *output_len) (*output)[j++] = triple & 0xFF;
    }
}