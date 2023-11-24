#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#define ALPHABET_SIZE 26
char encryptChar(char plaintext, int key) 
{
    if (isalpha(plaintext)) {
        char base = islower(plaintext) ? 'a' : 'A';
        return (plaintext - base + key) % ALPHABET_SIZE + base;
    } else {
        return plaintext; 
    }
}
void vigenereEncrypt(char *plaintext, int *key, char *ciphertext) 
{
    for (int i = 0; plaintext[i] != '\0'; ++i) 
	{
        ciphertext[i] = encryptChar(plaintext[i], key[i % ALPHABET_SIZE]);
    }
}

int main() {
    char plaintext[1000];
    int key[1000];
    char ciphertext[1000];
    printf("Enter the plaintext: ");
    fgets(plaintext, sizeof(plaintext), stdin);

    printf("Enter the key (stream of random numbers between 0 and 26, separated by spaces): ");
    for (int i = 0; i < ALPHABET_SIZE; ++i) {
        scanf("%d", &key[i]);
    }

    vigenereEncrypt(plaintext, key, ciphertext);
    printf("Encrypted Message: %s\n", ciphertext);

    return 0;
}

