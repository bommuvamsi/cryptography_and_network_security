#include <stdio.h>
#include <stdlib.h>
#include <string.h>
void encryptAffineCaesar(const char *plaintext, int a, int b, char *ciphertext) {
    int len = strlen(plaintext);

    for (int i = 0; i < len; i++) {
        if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') 
		{
            ciphertext[i] = ((a * (plaintext[i] - 'A') + b) % 26 + 26) % 26 + 'A';
        } else if (plaintext[i] >= 'a' && plaintext[i] <= 'z') 
		{
            ciphertext[i] = ((a * (plaintext[i] - 'a') + b) % 26 + 26) % 26 + 'a';
        } else 
		{
            ciphertext[i] = plaintext[i];
        }
    }
    ciphertext[len] = '\0';
}

int main() {
    const char *plaintext = "HelloWorld";
    int a = 5; 
    int b = 8; 

    int len = strlen(plaintext);
    char ciphertext[len + 1];

    encryptAffineCaesar(plaintext, a, b, ciphertext);

    printf("Plaintext:  %s\n", plaintext);
    printf("Key (a, b):  (%d, %d)\n", a, b);
    printf("Ciphertext: %s\n", ciphertext);

    return 0;
}

