#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

void multiplyMatrix(int key[2][2], int message[2], int result[2]) {
    result[0] = key[0][0] * message[0] + key[0][1] * message[1];
    result[1] = key[1][0] * message[0] + key[1][1] * message[1];
}
void encryptHillCipher(const char *message, int key[2][2], char *encrypted) {
    int len = strlen(message);
    int padded_len = (len % 2 == 0) ? len : len + 1; 
    int *messageVector = (int *)malloc(padded_len * sizeof(int));
    int *encryptedVector = (int *)malloc(padded_len * sizeof(int));

    for (int i = 0; i < len; i++) {
        messageVector[i] = message[i] - 'a';
    }

    if (padded_len > len) {
        messageVector[len] = 'x' - 'a'; 
    }

    for (int i = 0; i < padded_len; i += 2) {
        int messageBlock[2] = {messageVector[i], messageVector[i + 1]};
        int encryptedBlock[2];

        multiplyMatrix(key, messageBlock, encryptedBlock);

        encryptedBlock[0] = (encryptedBlock[0] + 26) % 26;
        encryptedBlock[1] = (encryptedBlock[1] + 26) % 26;

        encryptedVector[i] = encryptedBlock[0];
        encryptedVector[i + 1] = encryptedBlock[1];
    }
    for (int i = 0; i < padded_len; i++) {
        encrypted[i] = encryptedVector[i] + 'a';
    }

    encrypted[padded_len] = '\0';

    free(messageVector);
    free(encryptedVector);
}
int modInverse(int a, int m) {
    for (int i = 1; i < m; i++) {
        if ((a * i) % m == 1) {
            return i;
        }
    }
    return -1; 
}
int determinant(int key[2][2]) {
    return key[0][0] * key[1][1] - key[0][1] * key[1][0];
}
void adjugate(int key[2][2], int adj[2][2]) {
    adj[0][0] = key[1][1];
    adj[0][1] = -key[0][1];
    adj[1][0] = -key[1][0];
    adj[1][1] = key[0][0];
}
void decryptHillCipher(const char *encrypted, int key[2][2], char *decrypted) {
    int len = strlen(encrypted);
    int *encryptedVector = (int *)malloc(len * sizeof(int));
    int *decryptedVector = (int *)malloc(len * sizeof(int));

    for (int i = 0; i < len; i++) {
        encryptedVector[i] = encrypted[i] - 'a';
    }
    int keyDet = determinant(key);
    int keyDetInv = modInverse(keyDet, 26);

    if (keyDetInv == -1) {
        fprintf(stderr, "Error: Modular inverse does not exist. Cannot decrypt.\n");
        exit(EXIT_FAILURE);
    }

    int keyAdj[2][2];
    adjugate(key, keyAdj);

    for (int i = 0; i < len; i += 2) {
        int encryptedBlock[2] = {encryptedVector[i], encryptedVector[i + 1]};
        int decryptedBlock[2];

        multiplyMatrix(keyAdj, encryptedBlock, decryptedBlock);

        decryptedBlock[0] = (keyDetInv * decryptedBlock[0] + 26) % 26;
        decryptedBlock[1] = (keyDetInv * decryptedBlock[1] + 26) % 26;

        decryptedVector[i] = decryptedBlock[0];
        decryptedVector[i + 1] = decryptedBlock[1];
    }
    for (int i = 0; i < len; i++) {
        decrypted[i] = decryptedVector[i] + 'a';
    }

    decrypted[len] = '\0';

    free(encryptedVector);
    free(decryptedVector);
}

int main() {
    int key[2][2] = {{9, 4}, {5, 7}};

    const char *originalMessage = "meet me at the usual place at ten rather than eight oclock";
    char encryptedMessage[strlen(originalMessage)];
    char decryptedMessage[strlen(originalMessage)];

    encryptHillCipher(originalMessage, key, encryptedMessage);

    decryptHillCipher(encryptedMessage, key, decryptedMessage);

    printf("Original Message: %s\n", originalMessage);
    printf("Encrypted Message: %s\n", encryptedMessage);
    printf("Decrypted Message: %s\n", decryptedMessage);

    return 0;
}

