#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

// Function to encrypt a message using a one-time pad Vigenère cipher
void encrypt_vigenere_one_time_pad(const char *plaintext, const int *key, char *ciphertext) {
    for (int i = 0; plaintext[i] != '\0'; i++) {
        if (isalpha(plaintext[i])) {
            char base = isupper(plaintext[i]) ? 'A' : 'a';
            ciphertext[i] = (plaintext[i] - base + key[i % 26]) % 26 + base;
        } else {
            ciphertext[i] = plaintext[i]; // Non-alphabetic characters are not encrypted
        }
    }
}

int main() {
    // Example key (stream of random numbers between 0 and 26)
    int key[] = {3, 19, 5, 11, 7, 23, 2, 17, 8, 14, 20, 25, 1, 10, 15, 6, 13, 4, 18, 9, 16, 21, 12, 24, 22, 0};

    // Example plaintext
    const char *plaintext = "Hello, One-Time Pad Vigenere Cipher!";

    // Calculate the length of the plaintext
    int plaintext_length = 0;
    while (plaintext[plaintext_length] != '\0') {
        plaintext_length++;
    }

    // Allocate memory for the ciphertext
    char ciphertext[plaintext_length];

    // Encrypt the plaintext
    encrypt_vigenere_one_time_pad(plaintext, key, ciphertext);

    // Print the results
    printf("Plaintext: %s\n", plaintext);
    printf("Key: ");
    for (int i = 0; i < sizeof(key) / sizeof(key[0]); i++) {
        printf("%d ", key[i]);
    }
    printf("\n");
    printf("Ciphertext: %s\n", ciphertext);

    return 0;
}

