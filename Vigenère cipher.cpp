#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void encryptVigenereOneTimePad(const char *plaintext, const int *key, char *ciphertext) {
    int len = strlen(plaintext);

    for (int i = 0; i < len; i++) {
        if (plaintext[i] == ' ') {

            ciphertext[i] = ' ';
            continue;
        }

        int shift = key[i % len];
        char base;

        if (plaintext[i] >= 'a' && plaintext[i] <= 'z') {
            base = 'a';
        } else if (plaintext[i] >= 'A' && plaintext[i] <= 'Z') {
            base = 'A';
        } else {
            ciphertext[i] = plaintext[i];
            continue;
        }

        ciphertext[i] = (plaintext[i] - base + shift) % 26 + base;
    }

    ciphertext[len] = '\0';
}

int main() {
    const char *plaintext = "sendmoremoney";
    const int key[] = {9, 0, 1, 7, 23, 15, 21, 14, 11, 11, 2, 8, 9};
    char ciphertext[strlen(plaintext)];

    encryptVigenereOneTimePad(plaintext, key, ciphertext);

    printf("Encrypted Ciphertext: %s\n", ciphertext);

    return 0;
}

