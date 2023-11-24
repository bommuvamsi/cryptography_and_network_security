#include <stdio.h>
#include <string.h>
#include <openssl/aes.h> 

void aes_ctr_encrypt(const unsigned char *input, const unsigned char *key, const unsigned char *nonce, unsigned char *output, size_t length) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);

    unsigned char counter[AES_BLOCK_SIZE];
    memcpy(counter, nonce, AES_BLOCK_SIZE);

    for (size_t i = 0; i < length; i += AES_BLOCK_SIZE) {
        AES_encrypt(counter, output + i, &aesKey);
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            output[i + j] ^= input[i + j];
        }

        // Increment the counter (little-endian)
        for (int j = AES_BLOCK_SIZE - 1; j >= 0; j--) {
            if (++counter[j]) {
                break;
            }
        }
    }
}

void aes_ctr_decrypt(const unsigned char *ciphertext, const unsigned char *key, const unsigned char *nonce, unsigned char *plaintext, size_t length) {
    aes_ctr_encrypt(ciphertext, key, nonce, plaintext, length);
}

int main() {
    // Your plaintext, key, and nonce (counter)
    const char *plaintext = "This is a CTR mode example.";
    const unsigned char key[16] = "0123456789abcdef";
    const unsigned char nonce[16] = "abcdefghijklmnop";

    size_t plaintextLen = strlen(plaintext);
    unsigned char ciphertext[plaintextLen];
    unsigned char decryptedText[plaintextLen];

    // Encrypt in CTR mode
    aes_ctr_encrypt(plaintext, key, nonce, ciphertext, plaintextLen);

    printf("Plaintext: %s\n", plaintext);
    printf("Ciphertext (hex): ");
    for (size_t i = 0; i < plaintextLen; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\n");

    // Decrypt the ciphertext
    aes_ctr_decrypt(ciphertext, key, nonce, decryptedText, plaintextLen);
    printf("Decrypted Text: %s\n", decryptedText);

    return 0;
}
