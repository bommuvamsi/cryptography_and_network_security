#include <stdio.h>
#include <string.h>
#include <openssl/des.h>

void encrypt3DES_CBC(const char *plaintext, const char *key, const char *iv, char *ciphertext) {
    DES_key_schedule ks1, ks2, ks3;
    DES_cblock desIV, inputBlock, outputBlock;

    // Set the keys and IV
    DES_set_key_unchecked((const_DES_cblock *)key, &ks1);
    DES_set_key_unchecked((const_DES_cblock *)(key + 8), &ks2);
    DES_set_key_unchecked((const_DES_cblock *)(key + 16), &ks3);

    memcpy(desIV, iv, 8);

    // Get the length of the plaintext
    size_t len = strlen(plaintext);

    // Encrypt each block in CBC mode
    for (size_t i = 0; i < len; i += 8) {
        // XOR the plaintext block with the previous ciphertext block (or IV for the first block)
        for (int j = 0; j < 8; j++) {
            inputBlock[j] = plaintext[i + j] ^ desIV[j];
        }

        // Encrypt the block using 3DES
        DES_ecb3_encrypt(&inputBlock, &outputBlock, &ks1, &ks2, &ks3, DES_ENCRYPT);

        // Copy the ciphertext block to the output
        memcpy(ciphertext + i, outputBlock, 8);

        // Update the IV for the next iteration
        memcpy(desIV, outputBlock, 8);
    }
}

int main() {
    const char *plaintext = "This is a message";
    const char *key = "0123456789abcdef0123456789abcdef0123456789abcdef";
    const char *iv = "12345678";
    char ciphertext[256];

    encrypt3DES_CBC(plaintext, key, iv, ciphertext);

    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext: ");
    for (int i = 0; i < strlen(plaintext) + 16; i++) {
        printf("%02x", (unsigned char)ciphertext[i]);
    }
    printf("\n");

    return 0;
}

