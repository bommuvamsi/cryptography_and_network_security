#include <stdio.h>
#include <string.h>
void xor_block(const unsigned char *input, const unsigned char *key, unsigned char *output) 
{
    for (int i = 0; i < 16; ++i) 
	{
        output[i] = input[i] ^ key[i];
    }
}
void cbc_mac(const unsigned char *key, const unsigned char *message, unsigned char *mac) 
{
    unsigned char iv[16] = {0};  
    xor_block(message, iv, mac);  
}

int main() 
{
    unsigned char key[16] = "ThisIsTheSecret";
    unsigned char message[16] = "OneBlockMessage";
    unsigned char mac[16];
    cbc_mac(key, message, mac);
    printf("CBC-MAC for One-Block Message: ");
    for (int i = 0; i < 16; ++i) 
	{
        printf("%02x", mac[i]);
    }
    printf("\n");
    unsigned char two_block_message[32];
    memcpy(two_block_message, message, 16);  
    xor_block(message, mac, two_block_message + 16);  
    unsigned char two_block_mac[16];
    cbc_mac(key, two_block_message, two_block_mac);
    printf("CBC-MAC for Two-Block Message: ");
    for (int i = 0; i < 16; ++i) 
	{
        printf("%02x", two_block_mac[i]);
    }
    printf("\n");

    return 0;
}

