#include <stdio.h>
#include <string.h>
#include <"mbedtls/aes.h">

void encrypt(const unsigned char *input, const unsigned char *key, const unsigned char *iv, unsigned char *output, size_t length, int mode) {
    mbedtls_aes_context aes_ctx;

    mbedtls_aes_init(&aes_ctx);

    mbedtls_aes_setkey_enc(&aes_ctx, key, 128);

    if (mode == MBEDTLS_AES_ENCRYPT) {
        mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_ENCRYPT, input, output);
    } else {
        mbedtls_aes_crypt_ecb(&aes_ctx, MBEDTLS_AES_DECRYPT, input, output);
    }

    mbedtls_aes_free(&aes_ctx);
}

int main() {
    const unsigned char key[16] = "0123456789abcdef";
    const unsigned char iv[16] = "1234567890123456";
    const unsigned char input[16] = "Hello, Padding!";
    unsigned char encrypted_output[16];
    unsigned char decrypted_output[16];

    // ECB mode
    encrypt(input, key, iv, encrypted_output, sizeof(input), MBEDTLS_AES_ENCRYPT);
    encrypt(encrypted_output, key, iv, decrypted_output, sizeof(encrypted_output), MBEDTLS_AES_DECRYPT);
    printf("ECB Original: %s\n", input);
    printf("ECB Encrypted: ");
    for (size_t i = 0; i < sizeof(input); i++) {
        printf("%02x", encrypted_output[i]);
    }
    printf("\n");
    printf("ECB Decrypted: %s\n", decrypted_output);

    // CBC mode
    encrypt(input, key, iv, encrypted_output, sizeof(input), MBEDTLS_AES_ENCRYPT);
    encrypt(encrypted_output, key, iv, decrypted_output, sizeof(encrypted_output), MBEDTLS_AES_DECRYPT);
    printf("\nCBC Original: %s\n", input);
    printf("CBC Encrypted: ");
    for (size_t i = 0; i < sizeof(input); i++) {
        printf("%02x", encrypted_output[i]);
    }
    printf("\n");
    printf("CBC Decrypted: %s\n", decrypted_output);

    // CFB mode
    encrypt(input, key, iv, encrypted_output, sizeof(input), MBEDTLS_AES_ENCRYPT);
    encrypt(encrypted_output, key, iv, decrypted_output, sizeof(encrypted_output), MBEDTLS_AES_DECRYPT);
    printf("\nCFB Original: %s\n", input);
    printf("CFB Encrypted: ");
    for (size_t i = 0; i < sizeof(input); i++) {
        printf("%02x", encrypted_output[i]);
    }
    printf("\n");
    printf("CFB Decrypted: %s\n", decrypted_output);

    return 0;
}

