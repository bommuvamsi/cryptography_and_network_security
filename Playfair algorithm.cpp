#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SIZE 5

void prepareKey(char key[], char keyMatrix[SIZE][SIZE]);
void generateKeyMatrix(char key[], char keyMatrix[SIZE][SIZE]);
void findPosition(char keyMatrix[SIZE][SIZE], char ch, int position[2]);
void encrypt(char keyMatrix[SIZE][SIZE], char pair[2]);

int main() {
    char key[100], plaintext[100];
    char keyMatrix[SIZE][SIZE];

    printf("Enter the key for Playfair cipher: ");
    fgets(key, sizeof(key), stdin);

    key[strcspn(key, "\n")] = '\0';

    prepareKey(key, keyMatrix);

    printf("Enter the plaintext to encrypt: ");
    fgets(plaintext, sizeof(plaintext), stdin);

    plaintext[strcspn(plaintext, "\n")] = '\0';

    printf("Encrypted Text: ");
    for (int i = 0; i < strlen(plaintext); i += 2) {
        char pair[2] = {plaintext[i], plaintext[i + 1]};
        encrypt(keyMatrix, pair);
    }

    return 0;
}

void prepareKey(char key[], char keyMatrix[SIZE][SIZE]) {
    int k = 0;
    char keySet[26] = {0};

    for (int i = 0; i < strlen(key); i++) {
        if (keySet[key[i] - 'A'] == 0 && key[i] != ' ') {
            keySet[key[i] - 'A'] = 1;
            key[k++] = key[i];
        }
    }

    for (char ch = 'A'; ch <= 'Z'; ch++) {
        if (ch != 'J' && keySet[ch - 'A'] == 0) {
            key[k++] = ch;
        }
    }

    generateKeyMatrix(key, keyMatrix);
}

void generateKeyMatrix(char key[], char keyMatrix[SIZE][SIZE]) {
    int k = 0;

    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            keyMatrix[i][j] = key[k++];
            printf("%c ", keyMatrix[i][j]);
        }
        printf("\n");
    }
}

void findPosition(char keyMatrix[SIZE][SIZE], char ch, int position[2]) {
    if (ch == 'J')
        ch = 'I';

    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            if (keyMatrix[i][j] == ch) {
                position[0] = i;
                position[1] = j;
                return;
            }
        }
    }
}

void encrypt(char keyMatrix[SIZE][SIZE], char pair[2]) {
    int pos1[2], pos2[2];

    findPosition(keyMatrix, pair[0], pos1);
    findPosition(keyMatrix, pair[1], pos2);

    if (pos1[0] == pos2[0]) {
        printf("%c%c ", keyMatrix[pos1[0]][(pos1[1] + 1) % SIZE], keyMatrix[pos2[0]][(pos2[1] + 1) % SIZE]);
    }
    else if (pos1[1] == pos2[1]) {
        printf("%c%c ", keyMatrix[(pos1[0] + 1) % SIZE][pos1[1]], keyMatrix[(pos2[0] + 1) % SIZE][pos2[1]]);
    }

    else {
        printf("%c%c ", keyMatrix[pos1[0]][pos2[1]], keyMatrix[pos2[0]][pos1[1]]);
    }
}

