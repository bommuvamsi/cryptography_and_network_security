#include <stdio.h>
#include <string.h>
#include <ctype.h>

void encryptVigenere(char plaintext[], char key[]);
char shiftChar(char c, int shift);

int main() {
    char plaintext[100], key[100];

    printf("Enter the plaintext to encrypt: ");
    fgets(plaintext, sizeof(plaintext), stdin);

    plaintext[strcspn(plaintext, "\n")] = '\0';

    printf("Enter the key for Vigenere cipher: ");
    fgets(key, sizeof(key), stdin);

    key[strcspn(key, "\n")] = '\0';

    printf("Encrypted Text: ");
    encryptVigenere(plaintext, key);

    return 0;
}

void encryptVigenere(char plaintext[], char key[]) {
    int keyLength = strlen(key);
    int textLength = strlen(plaintext);

    for (int i = 0, j = 0; i < textLength; ++i) {
        char currentChar = plaintext[i];

        if (isalpha(currentChar)) {
            char keyChar = key[j % keyLength];
            int shift = toupper(keyChar) - 'A';

            char encryptedChar = shiftChar(currentChar, shift);
            printf("%c", encryptedChar);

            ++j;
        } else {
            printf("%c", currentChar);
        }
    }

    printf("\n");
}

char shiftChar(char c, int shift) {
    if (isupper(c)) {
        return ((c - 'A' + shift) % 26) + 'A';
    } else if (islower(c)) {
        return ((c - 'a' + shift) % 26) + 'a';
    } else {
        return c;
    }
}

