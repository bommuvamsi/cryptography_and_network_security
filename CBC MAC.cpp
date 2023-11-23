#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

// Function to calculate CBC-MAC for a one-block message
void calculate_cbc_mac(const unsigned char *key, const unsigned char *input, size_t input_size, unsigned char *mac) {
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher = EVP_aes_128_ecb(); // Assuming AES-128
    unsigned char iv[16] = {0}; // Initialization vector

    // Create and initialize the cipher context
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv);

    // Perform CBC encryption
    EVP_EncryptUpdate(ctx, mac, &input_size, input, input_size);

    // Finalize the CBC-MAC
    EVP_EncryptFinal_ex(ctx, mac, &input_size);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
}

int main() {
    // Example key and message
    unsigned char key[16] = "abcdefghijklmnop"; // 128-bit key
    unsigned char message[16] = "Hello, World!";

    // Calculate CBC-MAC for the one-block message
    unsigned char cbc_mac_one_block[16];
    calculate_cbc_mac(key, message, sizeof(message), cbc_mac_one_block);

    // Construct the two-block message X || (X ? T)
    unsigned char two_block_message[32];
    memcpy(two_block_message, message, sizeof(message));
    
    for (int i = 0; i < sizeof(cbc_mac_one_block); i++) {
        two_block_message[sizeof(message) + i] = message[i] ^ cbc_mac_one_block[i];
    }

    // Calculate CBC-MAC for the two-block message
    unsigned char cbc_mac_two_blocks[16];
    calculate_cbc_mac(key, two_block_message, sizeof(two_block_message), cbc_mac_two_blocks);

    // Print the results
    printf("CBC-MAC for one-block message: ");
    for (int i = 0; i < sizeof(cbc_mac_one_block); i++) {
        printf("%02x", cbc_mac_one_block[i]);
    }
    printf("\n");

    printf("CBC-MAC for two-block message: ");
    for (int i = 0; i < sizeof(cbc_mac_two_blocks); i++) {
        printf("%02x", cbc_mac_two_blocks[i]);
    }
    printf("\n");

    return 0;
}

