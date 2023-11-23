#include <stdio.h>
#include <string.h>

void findPosition(char playfair[5][5], char ch, int *row, int *col) {
    if (ch == 'J') {
        ch = 'I';
    }

    for (*row = 0; *row < 5; (*row)++) {
        for (*col = 0; *col < 5; (*col)++) {
            if (playfair[*row][*col] == ch) {
                return;
            }
        }
    }
}
void decodePlayfair(char playfair[5][5], char cipher[], char decoded[]) {
    int i;
    int row1, col1, row2, col2;

    for (i = 0; i < strlen(cipher); i += 2) {
        findPosition(playfair, cipher[i], &row1, &col1);
        findPosition(playfair, cipher[i + 1], &row2, &col2);

        if (row1 == row2) {
            decoded[i] = playfair[row1][(col1 - 1 + 5) % 5];
            decoded[i + 1] = playfair[row2][(col2 - 1 + 5) % 5];
        } else if (col1 == col2) {
            decoded[i] = playfair[(row1 - 1 + 5) % 5][col1];
            decoded[i + 1] = playfair[(row2 - 1 + 5) % 5][col2];
        } else {
            decoded[i] = playfair[row1][col2];
            decoded[i + 1] = playfair[row2][col1];
        }
    }
    decoded[i] = '\0';
}

int main() {
    char playfair[5][5] = {
        {'K', 'X', 'J', 'E', 'Y'},
        {'U', 'R', 'E', 'B', 'E'},
        {'Z', 'W', 'E', 'H', 'E'},
        {'W', 'R', 'Y', 'T', 'U'},
        {'H', 'E', 'Y', 'F', 'S'}
    };
    char cipher[] = "KXJEYUREBEZWEHEWRYTUHEYFSKREHEGOYFIWTTTUOLKSYCAJPOBOTEIZONTXBYBNTGONEYCUZWRGDSONSXBOUYWRHEBAAHYUSED";
    char decoded[strlen(cipher)];

    decodePlayfair(playfair, cipher, decoded);
    printf("Decoded Message: %s\n", decoded);

    return 0;
}

