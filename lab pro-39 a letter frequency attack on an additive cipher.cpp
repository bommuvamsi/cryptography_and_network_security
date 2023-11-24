#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALPHABET_SIZE 26
void calculateFrequency(const char *text, int *frequency) 
{
    int len = strlen(text);

    for (int i = 0; i < len; i++) 
	{
        if (text[i] >= 'A' && text[i] <= 'Z') 
		{
            frequency[text[i] - 'A']++;
        } else if (text[i] >= 'a' && text[i] <= 'z') 
		{
            frequency[text[i] - 'a']++;
        }
    }
}
void decryptAdditiveCipher(const char *ciphertext, int shift, char *plaintext) 
{
    int len = strlen(ciphertext);

    for (int i = 0; i < len; i++) 
	{
        if (ciphertext[i] >= 'A' && ciphertext[i] <= 'Z') 
		{
            plaintext[i] = ((ciphertext[i] - 'A' - shift + ALPHABET_SIZE) % ALPHABET_SIZE) + 'A';
        } else if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') {
            plaintext[i] = ((ciphertext[i] - 'a' - shift + ALPHABET_SIZE) % ALPHABET_SIZE) + 'a';
        } else 
		{
            plaintext[i] = ciphertext[i];
        }
    }

    plaintext[len] = '\0';
}
void letterFrequencyAttack(const char *ciphertext, int topPlaintexts) 
{
    int frequency[ALPHABET_SIZE] = {0};
    calculateFrequency(ciphertext, frequency);
    int maxFrequency = 0;
    int maxFrequencyIndex = 0;
    for (int i = 0; i < ALPHABET_SIZE; i++) 
	{
        if (frequency[i] > maxFrequency) 
		{
            maxFrequency = frequency[i];
            maxFrequencyIndex = i;
        }
    }

    int shift = (maxFrequencyIndex - ('E' - 'A') + ALPHABET_SIZE) % ALPHABET_SIZE;

    char plaintext[strlen(ciphertext) + 1];
    decryptAdditiveCipher(ciphertext, shift, plaintext);

    printf("Top %d Possible Plaintexts (Shift = %d):\n", topPlaintexts, shift);
    for (int i = 0; i < topPlaintexts; i++) {
        printf("%d: %s\n", i + 1, plaintext);
        shift = (shift + 1) % ALPHABET_SIZE; 
        decryptAdditiveCipher(ciphertext, shift, plaintext);
    }
}

int main() 
{
    const char *ciphertext = "Khoor Zruog";
    int topPlaintexts = 5;

    letterFrequencyAttack(ciphertext, topPlaintexts);

    return 0;
}

