#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALPHABET_SIZE 26

void calculateFrequency(const char *text, int *frequency) 
{
    int len = strlen(text);

    for (int i = 0; i < len; i++) {
        if (text[i] >= 'A' && text[i] <= 'Z') {
            frequency[text[i] - 'A']++;
        } else if (text[i] >= 'a' && text[i] <= 'z') {
            frequency[text[i] - 'a']++;
        }
    }
}

void decryptSubstitutionCipher(const char *ciphertext, char *plaintext, const char *mapping) 
{
    int len = strlen(ciphertext);

    for (int i = 0; i < len; i++) 
	{
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') 
		{
            plaintext[i] = mapping[ciphertext[i] - 'A'];
        } else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') 
		{
            plaintext[i] = mapping[ciphertext[i] - 'a'];
        } else {
            plaintext[i] = ciphertext[i];
        }
    }    plaintext[len] = '\0';
}
void letterFrequencyAttack(const char *ciphertext, int topPlaintexts) 
{
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
    for (int i = 0; i < ALPHABET_SIZE - 1; i++) 
	{
        for (int j = 0; j < ALPHABET_SIZE - i - 1; j++) 
		{
            if (letterFrequencies[j].frequency < letterFrequencies[j + 1].frequency) 
			{
                struct LetterFrequency temp = letterFrequencies[j];
                letterFrequencies[j] = letterFrequencies[j + 1];
                letterFrequencies[j + 1] = temp;
            }
        }
    }

    char substitutionMap[ALPHABET_SIZE];
    for (int i = 0; i < ALPHABET_SIZE; i++) 
	{
        substitutionMap[letterFrequencies[i].letter - 'A'] = 'A' + i;
    }

    char plaintext[strlen(ciphertext) + 1];
    decryptSubstitutionCipher(ciphertext, plaintext, substitutionMap);

    printf("Top %d Possible Plaintexts:\n", topPlaintexts);
    for (int i = 0; i < topPlaintexts; i++) 
	{
        printf("%d: %s\n", i + 1, plaintext);
    }
}

int main() 
{
    const char *ciphertext = "VJKUBKUBCUEJ";
    int topPlaintexts = 5;

    letterFrequencyAttack(ciphertext, topPlaintexts);

    return 0;
}

