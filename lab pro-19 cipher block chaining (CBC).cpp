#include <stdio.h>
#include <sodium/crypto_stream_chacha20.h>

void encrypt_3des_cbc(const unsigned char *input, const unsigned char *key, const unsigned char *iv, unsigned char *output, size_t length) {
    crypto_stream_chacha20_xor_ic(output, input, length, iv, 0, key);
}

int main() {
    if (sodium_init() < 0) {
        // panic! the library couldn't be initialized, it is not safe to use
        return 1;
    }

    const char *input = "Hello, CBC!";
    const unsigned char key[crypto_stream_chacha20_KEYBYTES] = "0123456789abcdef0123456789abcdef";
    const unsigned char iv[crypto_stream_chacha20_NONCEBYTES] = "123456789012";
    unsigned char encrypted_output[256];

    encrypt_3des_cbc((const unsigned char *)input, key, iv, encrypted_output, strlen(input));

    printf("Original: %s\n", input);
    printf("Encrypted: ");
    for (size_t i = 0; i < strlen(input); i++) {
        printf("%02x", (unsigned char)encrypted_output[i]);
    }
    printf("\n");

    return 0;
}

