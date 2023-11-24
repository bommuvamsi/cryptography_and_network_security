#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALPHABET_SIZE 26

// Function to encrypt a message using the one-time pad Vigenère cipher
void encryptVigenere(const char *plaintext, const int *key, char *ciphertext) {
    int len = strlen(plaintext);

    for (int i = 0; i < len; i++) {
        if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') {
            // Encrypt uppercase letters
            ciphertext[i] = (plaintext[i] + key[i % ALPHABET_SIZE] - 'A') % ALPHABET_SIZE + 'A';
        } else if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            // Encrypt lowercase letters
            ciphertext[i] = (plaintext[i] + key[i % ALPHABET_SIZE] - 'a') % ALPHABET_SIZE + 'a';
        } else {
            // Leave non-alphabetic characters unchanged
            ciphertext[i] = plaintext[i];
        }
    }

    // Null-terminate the ciphertext
    ciphertext[len] = '\0';
}

int main() {
    const char *plaintext = "HelloWorld";
    const int key[] = {3, 19, 5, 8, 12, 1, 15, 0, 9, 7, 25}; // Example key

    int len = strlen(plaintext);
    char ciphertext[len + 1];

    encryptVigenere(plaintext, key, ciphertext);

    printf("Plaintext:  %s\n", plaintext);
    printf("Key:        ");
    for (int i = 0; i < len; i++) {
        printf("%d ", key[i]);
    }
    printf("\n");
    printf("Ciphertext: %s\n", ciphertext);

    return 0;
}

