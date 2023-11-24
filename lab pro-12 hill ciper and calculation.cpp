#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define SIZE 2
#define MOD 26

void multiplyMatrix(int A[SIZE][SIZE], int B[SIZE], int result[SIZE]) 
{
    for (int i = 0; i < SIZE; i++) 
	{
        result[i] = 0;
        for (int j = 0; j < SIZE; j++) 
		{
            result[i] += A[i][j] * B[j];
            result[i] %= MOD;
        }
    }
}

void encrypt(char message[], int key[SIZE][SIZE], char encrypted[]) 
{
    int len = strlen(message);
    if (len % 2 != 0) {
        message[len] = 'X';
        message[len + 1] = '\0';
        len++;
    }

    for (int i = 0; i < len; i += 2) {
        int pair[SIZE] = {toupper(message[i]) - 'A', toupper(message[i + 1]) - 'A'};
        int result[SIZE];

        multiplyMatrix(key, pair, result);

        encrypted[i] = result[0] + 'A';
        encrypted[i + 1] = result[1] + 'A';
    }
    encrypted[len] = '\0';
}

int calculateDeterminant(int key[SIZE][SIZE]) {
    return key[0][0] * key[1][1] - key[0][1] * key[1][0];
}

void inverseMatrix(int key[SIZE][SIZE], int inverse[SIZE][SIZE]) {
    int det = calculateDeterminant(key);
    int detInv = 0;

    for (int i = 0; i < MOD; i++) {
        if ((det * i) % MOD == 1) {
            detInv = i;
            break;
        }
    }

    inverse[0][0] = key[1][1] * detInv % MOD;
    inverse[1][1] = key[0][0] * detInv % MOD;
    inverse[0][1] = (MOD - key[0][1]) * detInv % MOD;
    inverse[1][0] = (MOD - key[1][0]) * detInv % MOD;
}

void decrypt(char encrypted[], int key[SIZE][SIZE], char decrypted[]) {
    int inverse[SIZE][SIZE];
    inverseMatrix(key, inverse);

    int len = strlen(encrypted);

    for (int i = 0; i < len; i += 2) {
        int pair[SIZE] = {encrypted[i] - 'A', encrypted[i + 1] - 'A'};
        int result[SIZE];

        multiplyMatrix(inverse, pair, result);

        decrypted[i] = result[0] + 'A';
        decrypted[i + 1] = result[1] + 'A';
    }
    decrypted[len] = '\0';
}

int main() {
    char message[] = "meet me at the usual place at ten rather than eight o'clock";
    int key[SIZE][SIZE] = {{9, 4}, {5, 7}};

    char encrypted[100];
    char decrypted[100];

    encrypt(message, key, encrypted);
    decrypt(encrypted, key, decrypted);

    printf("Original Message: %s\n", message);
    printf("Encrypted Message: %s\n", encrypted);
    printf("Decrypted Message: %s\n", decrypted);

    return 0;
}

