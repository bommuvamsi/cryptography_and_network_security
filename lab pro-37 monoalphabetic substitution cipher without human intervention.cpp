#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALPHABET_SIZE 26
void calculateFrequency(const char *text, int *frequency) {
    int len = strlen(text);

    for (int i = 0; i < len; i++) {
        if (text[i] >= 'A' && text[i] <= 'Z') {
            frequency[text[i] - 'A']++;
        } else if (text[i] >= 'a' && text[i] <= 'z') {
            frequency[text[i] - 'a']++;
        }
    }
}
void letterFrequencyAttack(const char *ciphertext, char *plaintext) {
    int frequency[ALPHABET_SIZE] = {0};
    calculateFrequency(ciphertext, frequency);
    struct LetterFrequency {
        char letter;
        int frequency;
    } letterFrequencies[ALPHABET_SIZE];

    for (int i = 0; i < ALPHABET_SIZE; i++) {
        letterFrequencies[i].letter = 'A' + i;
        letterFrequencies[i].frequency = frequency[i];
    }
    for (int i = 0; i < ALPHABET_SIZE - 1; i++) {
        for (int j = 0; j < ALPHABET_SIZE - i - 1; j++) {
            if (letterFrequencies[j].frequency < letterFrequencies[j + 1].frequency) {
                struct LetterFrequency temp = letterFrequencies[j];
                letterFrequencies[j] = letterFrequencies[j + 1];
                letterFrequencies[j + 1] = temp;
            }
        }
    }
    printf("Letter Frequencies (Descending Order):\n");
    for (int i = 0; i < ALPHABET_SIZE; i++) 
	{
        printf("%c: %d\n", letterFrequencies[i].letter, letterFrequencies[i].frequency);
    }
    char substitutionMap[ALPHABET_SIZE];
    for (int i = 0; i < ALPHABET_SIZE; i++) {
        substitutionMap[letterFrequencies[i].letter - 'A'] = 'A' + i;
    }
    int len = strlen(ciphertext);
    for (int i = 0; i < len; i++) {
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') {
            plaintext[i] = substitutionMap[ciphertext[i] - 'A'];
        } else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            plaintext[i] = substitutionMap[ciphertext[i] - 'a'] + 32; 
        } else {
            plaintext[i] = ciphertext[i]; 
        }
    }
    plaintext[len] = '\0';
}

int main() {
    const char *ciphertext = "Gur svefg zlfgrel bs gur Wvapn vf gur Qrpbaqrag";
    char plaintext[strlen(ciphertext) + 1];

    letterFrequencyAttack(ciphertext, plaintext);

    printf("\nTop 10 Possible Plaintexts:\n");
    for (int i = 0; i < 10; i++) {
        printf("%d: %s\n", i + 1, plaintext);
    }

    return 0;
}

