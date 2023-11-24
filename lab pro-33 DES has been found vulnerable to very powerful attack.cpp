#include <stdio.h>
#include <string.h>
#include <openssl/des.h>

void des_encrypt(const unsigned char *input, const unsigned char *key, unsigned char *output);
void des_decrypt(const unsigned char *input, const unsigned char *key, unsigned char *output);

int main() 
{
    unsigned char key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};

    unsigned char plaintext[8] = "OpenSSL";

    unsigned char ciphertext[8];
    unsigned char decryptedtext[8];

    des_encrypt(plaintext, key, ciphertext);

    printf("Encrypted Text: ");
    for (int i = 0; i < 8; i++) 
	{
        printf("%02x ", ciphertext[i]);
    }
    printf("\n");

    des_decrypt(ciphertext, key, decryptedtext);

    printf("Decrypted Text: %s\n", decryptedtext);

    return 0;
}

void des_encrypt(const unsigned char *input, const unsigned char *key, unsigned char *output) 
{
    DES_cblock des_key;
    DES_key_schedule key_schedule;

    memcpy(des_key, key, 8);
    DES_set_key(&des_key, &key_schedule);

    DES_encrypt1(input, &key_schedule, output);
}

void des_decrypt(const unsigned char *input, const unsigned char *key, unsigned char *output) 
{
    DES_cblock des_key;
    DES_key_schedule key_schedule;

    memcpy(des_key, key, 8);
    DES_set_key(&des_key, &key_schedule);

    DES_decrypt1(input, &key_schedule, output);
}

