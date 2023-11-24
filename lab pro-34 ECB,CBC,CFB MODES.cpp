#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>

#define AES_BLOCK_SIZE 16

void print_hex(const char* label, const void* data, size_t size) {
    printf("%s: ", label);
    for (size_t i = 0; i < size; ++i) {
        printf("%02X", ((const uint8_t*)data)[i]);
    }
    printf("\n");
}

void aes_encrypt_ecb(const uint8_t* plaintext, const uint8_t* key, uint8_t* ciphertext, size_t size) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_encrypt(plaintext + i, ciphertext + i, &aes_key);
    }
}

void aes_decrypt_ecb(const uint8_t* ciphertext, const uint8_t* key, uint8_t* plaintext, size_t size) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);

    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_decrypt(ciphertext + i, plaintext + i, &aes_key);
    }
}

void aes_encrypt_cbc(const uint8_t* plaintext, const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, size_t size) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    uint8_t previous_block[AES_BLOCK_SIZE];
    memcpy(previous_block, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            plaintext[i + j] ^= previous_block[j];
        }

        AES_encrypt(plaintext + i, ciphertext + i, &aes_key);

        memcpy(previous_block, ciphertext + i, AES_BLOCK_SIZE);
    }
}

void aes_decrypt_cbc(const uint8_t* ciphertext, const uint8_t* key, const uint8_t* iv, uint8_t* plaintext, size_t size) {
    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);

    uint8_t previous_block[AES_BLOCK_SIZE];
    memcpy(previous_block, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_decrypt(ciphertext + i, plaintext + i, &aes_key);

        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            plaintext[i + j] ^= previous_block[j];
        }

        memcpy(previous_block, ciphertext + i, AES_BLOCK_SIZE);
    }
}

void aes_encrypt_cfb(const uint8_t* plaintext, const uint8_t* key, const uint8_t* iv, uint8_t* ciphertext, size_t size) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    uint8_t feedback[AES_BLOCK_SIZE];
    memcpy(feedback, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_encrypt(feedback, feedback, &aes_key);

        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            ciphertext[i + j] = plaintext[i + j] ^ feedback[j];
        }

        memcpy(feedback, ciphertext + i, AES_BLOCK_SIZE);
    }
}

void aes_decrypt_cfb(const uint8_t* ciphertext, const uint8_t* key, const uint8_t* iv, uint8_t* plaintext, size_t size) {
    AES_KEY aes_key;
    AES_set_encrypt_key(key, 128, &aes_key);

    uint8_t feedback[AES_BLOCK_SIZE];
    memcpy(feedback, iv, AES_BLOCK_SIZE);

    for (size_t i = 0; i < size; i += AES_BLOCK_SIZE) {
        AES_encrypt(feedback, feedback, &aes_key);

        for (size_t j = 0; j < AES_BLOCK_SIZE; ++j) {
            plaintext[i + j] = ciphertext[i + j] ^ feedback[j];
        }

        memcpy(feedback, ciphertext + i, AES_BLOCK_SIZE);
    }
}

int main() {
    const uint8_t plaintext[] = "This is a sample text";
    const uint8_t key[AES_BLOCK_SIZE] = "0123456789abcdef";
    const uint8_t iv[AES_BLOCK_SIZE] = "fedcba9876543210";

    size_t size = strlen((char*)plaintext);
    size_t padded_size = (size / AES_BLOCK_SIZE + 1) * AES_BLOCK_SIZE;

    uint8_t ciphertext_ecb[padded_size];
    uint8_t ciphertext_cbc[padded_size];
    uint8_t ciphertext_cfb[padded_size];
    uint8_t decrypted_ecb[padded_size];
    uint8_t decrypted_cbc[padded_size];
    uint8_t decrypted_cfb[padded_size];

    // ECB mode
    aes_encrypt_ecb(plaintext, key, ciphertext_ecb, padded_size);
    aes_decrypt_ecb(ciphertext_ecb, key, decrypted_ecb, padded_size);

    print_hex("Plaintext", plaintext, size);
    print_hex("Encrypted ECB", ciphertext_ecb, padded_size);
    print_hex("Decrypted ECB", decrypted_ecb, padded_size);

    // CBC mode
    aes_encrypt_cbc(plaintext, key, iv, ciphertext_cbc, padded_size);
    aes_decrypt_cbc(ciphertext_cbc, key, iv, decrypted_cbc, padded_size);

    print_hex("Encrypted CBC", ciphertext_cbc, padded_size);
    print_hex("Decrypted CBC", decrypted_cbc, padded_size);

    // CFB mode
    aes_encrypt_cfb(plaintext, key, iv, ciphertext_cfb, padded_size);
    aes_decrypt_cfb(ciphertext_cfb, key, iv, decrypted_cfb, padded_size);

    print_hex("Encrypted CFB", ciphertext_cfb, padded_size);
    print_hex("Decrypted CFB", decrypted_cfb, padded_size);

    return 0;
}

