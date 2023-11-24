#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>

void encrypt_ecb(const char *input, const char *key, char *output) {
    DES_cblock des_key;
    DES_key_schedule ks;

    // Initialize the key
    memcpy(des_key, key, 8);

    // Set up the key schedule
    DES_set_key_unchecked(&des_key, &ks);

    // ECB mode encryption
    for (int i = 0; i < strlen(input); i += 8) {
        DES_ecb_encrypt((const_DES_cblock *)(input + i), (DES_cblock *)(output + i), &ks, DES_ENCRYPT);
    }
}

void decrypt_ecb(const char *input, const char *key, char *output) {
    DES_cblock des_key;
    DES_key_schedule ks;

    // Initialize the key
    memcpy(des_key, key, 8);

    // Set up the key schedule
    DES_set_key_unchecked(&des_key, &ks);

    // ECB mode decryption
    for (int i = 0; i < strlen(input); i += 8) {
        DES_ecb_encrypt((const_DES_cblock *)(input + i), (DES_cblock *)(output + i), &ks, DES_DECRYPT);
    }
}

int main() {
    const char *input = "HelloECB!";
    const char *key = "01234567";
    char encrypted_output[256];
    char decrypted_output[256];

    encrypt_ecb(input, key, encrypted_output);
    decrypt_ecb(encrypted_output, key, decrypted_output);

    printf("Original: %s\n", input);
    printf("Encrypted: %s\n", encrypted_output);
    printf("Decrypted: %s\n", decrypted_output);

    return 0;
}

