#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define ALPHABET_SIZE 26

void calculateLetterFrequencies(const char *text, int *frequencies) {
    for (int i = 0; text[i] != '\0'; ++i) {
        if (isalpha(text[i])) {
            char letter = tolower(text[i]);
            frequencies[letter - 'a']++;
        }
    }
}
void letterFrequencyAttack(const char *ciphertext, int topN) {
    int frequencies[ALPHABET_SIZE] = {0};
    calculateLetterFrequencies(ciphertext, frequencies);
    struct FrequencyPair {
        char letter;
        int frequency;
    };
    struct FrequencyPair frequencyPairs[ALPHABET_SIZE];
    for (int i = 0; i < ALPHABET_SIZE; ++i) {
        frequencyPairs[i].letter = 'a' + i;
        frequencyPairs[i].frequency = frequencies[i];
    }
    for (int i = 0; i < ALPHABET_SIZE - 1; ++i) {
        for (int j = i + 1; j < ALPHABET_SIZE; ++j) {
            if (frequencyPairs[j].frequency > frequencyPairs[i].frequency) {
                struct FrequencyPair temp = frequencyPairs[i];
                frequencyPairs[i] = frequencyPairs[j];
                frequencyPairs[j] = temp;
            }
        }
    }
    printf("Top %d Possible Plaintexts:\n", topN);
    for (int i = 0; i < topN; ++i) {
        printf("%d. ", i + 1);
        for (int j = 0; ciphertext[j] != '\0'; ++j) {
            if (isalpha(ciphertext[j])) {
                char letter = tolower(ciphertext[j]);
                char decryptedLetter = 'a' + (letter - 'a' + (frequencyPairs[i].letter - 'a')) % ALPHABET_SIZE;
                if (isupper(ciphertext[j])) {
                    decryptedLetter = toupper(decryptedLetter);
                }
                printf("%c", decryptedLetter);
            } else {
                printf("%c", ciphertext[j]);
            }
        }

        printf("\n");
    }
}

int main() {
    char ciphertext[1000];
    int topN;
    printf("Enter the ciphertext: ");
    fgets(ciphertext, sizeof(ciphertext), stdin);
    printf("Enter the number of possible plaintexts to display: ");
    scanf("%d", &topN);

    letterFrequencyAttack(ciphertext, topN);

    return 0;
}

