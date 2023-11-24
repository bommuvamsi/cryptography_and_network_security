#include <stdio.h>

#define BLOCK_SIZE_64  8
#define BLOCK_SIZE_128 16

void generateSubkeys(const unsigned char *key, unsigned char *subkey1, unsigned char *subkey2, int block_size);

int main() 
{
    unsigned char key_64[BLOCK_SIZE_64] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6};
    unsigned char key_128[BLOCK_SIZE_128] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x97, 0x1f, 0x97, 0x1f, 0x97, 0x1f};

    unsigned char subkey1[BLOCK_SIZE_64];
    unsigned char subkey2[BLOCK_SIZE_64];

    generateSubkeys(key_64, subkey1, subkey2, BLOCK_SIZE_64);

    printf("Subkey 1 (64 bits): ");
    for (int i = 0; i < BLOCK_SIZE_64; i++) 
	{
        printf("%02x ", subkey1[i]);
    }
    printf("\n");

    printf("Subkey 2 (64 bits): ");
    for (int i = 0; i < BLOCK_SIZE_64; i++) 
	{
        printf("%02x ", subkey2[i]);
    }
    printf("\n");
    generateSubkeys(key_128, subkey1, subkey2, BLOCK_SIZE_128);

    printf("Subkey 1 (128 bits): ");
    for (int i = 0; i < BLOCK_SIZE_128; i++) 
	{
        printf("%02x ", subkey1[i]);
    }
    printf("\n");

    printf("Subkey 2 (128 bits): ");
    for (int i = 0; i < BLOCK_SIZE_128; i++) 
	{
        printf("%02x ", subkey2[i]);
    }
    printf("\n");

    return 0;
}

void generateSubkeys(const unsigned char *key, unsigned char *subkey1, unsigned char *subkey2, int block_size) {
    for (int i = 0; i < block_size; i++) 
	{
        subkey1[i] = (key[i] << 1) ^ ((key[(i + 1) % block_size] & 0x80) ? 0x1B : 0x00);
    }

    for (int i = 0; i < block_size; i++) 
	{
        subkey2[i] = (subkey1[i] << 1) ^ ((subkey1[(i + 1) % block_size] & 0x80) ? 0x1B : 0x00);
    }
}

