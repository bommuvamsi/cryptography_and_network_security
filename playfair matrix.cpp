#include <stdio.h>
#include <string.h>

void findPosition(char playfair[5][5], char ch, int *row, int *col) {
    if (ch == 'J') ch = 'I';
    for (*row = 0; *row < 5; (*row)++) {
        for (*col = 0; *col < 5; (*col)++) {
            if (playfair[*row][*col] == ch) {
                return;
            }
        }
    }
}
void encryptPair(char playfair[5][5], char a, char b, char *result) {
    int row1, col1, row2, col2;

    findPosition(playfair, a, &row1, &col1);
    findPosition(playfair, b, &row2, &col2);

    if (row1 == row2) {
        result[0] = playfair[row1][(col1 + 1) % 5];
        result[1] = playfair[row2][(col2 + 1) % 5];
    } else if (col1 == col2) {
        result[0] = playfair[(row1 + 1) % 5][col1];
        result[1] = playfair[(row2 + 1) % 5][col2];
    } else {
        result[0] = playfair[row1][col2];
        result[1] = playfair[row2][col1];
    }
}
void encryptMessage(char playfair[5][5], const char *message, char *encrypted) {
    int i;
    for (i = 0; i < strlen(message); i += 2) {
        if (message[i] == ' ') {
        
            encrypted[i] = ' ';
            encrypted[i + 1] = ' ';
        } else {
            encryptPair(playfair, message[i], message[i + 1], &encrypted[i]);
        }
    }
    encrypted[i] = '\0';
}

int main() {
    char playfair[5][5] = {
        {'M', 'F', 'H', 'I', 'K'},
        {'U', 'N', 'O', 'P', 'Q'},
        {'Z', 'V', 'W', 'X', 'Y'},
        {'E', 'L', 'A', 'R', 'G'},
        {'D', 'S', 'T', 'B', 'C'}
    };

    const char *message = "Must see you over Cadogan West. Coming at once";
    char encrypted[strlen(message)];

    encryptMessage(playfair, message, encrypted);

    printf("Original Message: %s\n", message);
    printf("Encrypted Message: %s\n", encrypted);

    return 0;
}

