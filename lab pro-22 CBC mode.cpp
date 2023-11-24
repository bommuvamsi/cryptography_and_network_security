#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>

void encryptAES_CBC(const unsigned char *input, const unsigned char *key, const unsigned char *iv, unsigned char *output, size_t length) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);

    unsigned char xorBlock[AES_BLOCK_SIZE];
    memcpy(xorBlock, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < length; i += AES_BLOCK_SIZE) {
        // XOR the input with the previous ciphertext (or IV for the first block)
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            input[i + j] ^= xorBlock[j];
        }

        // Encrypt the XORed block
        AES_encrypt(input + i, output + i, &aesKey);

        // Update the XOR block with the ciphertext
        memcpy(xorBlock, output + i, AES_BLOCK_SIZE);
    }
}

int main() {
    // Your plaintext, key, and initialization vector (IV)
    const char *plaintext = "This is a simple example.";
    const unsigned char key[16] = "0123456789abcdef";
    const unsigned char iv[16] = "0123456789abcdef";

    size_t plaintextLen = strlen(plaintext);
    unsigned char ciphertext[plaintextLen];

    // Ensure the plaintext length is a multiple of AES_BLOCK_SIZE
    size_t paddedLen = ((plaintextLen + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;

    // Pad the plaintext if necessary
    unsigned char paddedPlaintext[paddedLen];
    memcpy(paddedPlaintext, plaintext, plaintextLen);
    memset(paddedPlaintext + plaintextLen, 0, paddedLen - plaintextLen);

    encryptAES_CBC(paddedPlaintext, key, iv, ciphertext, paddedLen);

    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < paddedLen; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");

    return 0;
}
