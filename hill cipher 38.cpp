#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#define MOD 26

// Function to calculate the modular inverse of a number
int mod_inverse(int a, int m) {
    for (int i = 1; i < m; i++) {
        if ((a * i) % m == 1) {
            return i;
        }
    }
    return -1; // Inverse doesn't exist
}

// Function to find the determinant of a 2x2 matrix
int determinant(int a, int b, int c, int d) {
    return (a * d - b * c + MOD) % MOD;
}

// Function to find the adjugate of a 2x2 matrix
void adjugate(int a, int b, int c, int d, int* adj_a, int* adj_b, int* adj_c, int* adj_d) {
    *adj_a = d;
    *adj_b = (MOD - b) % MOD;
    *adj_c = (MOD - c) % MOD;
    *adj_d = a;
}

// Function to decrypt a 2x2 Hill cipher
void decrypt_hill(int ciphertext[], int key[]) {
    int inverse = mod_inverse(determinant(key[0], key[1], key[2], key[3]), MOD);
    
    if (inverse == -1) {
        printf("Inverse doesn't exist. The key is not invertible.\n");
        return;
    }

    int adj_a, adj_b, adj_c, adj_d;
    adjugate(key[0], key[1], key[2], key[3], &adj_a, &adj_b, &adj_c, &adj_d);

    int inverse_key[4] = {adj_a, adj_b, adj_c, adj_d};

    // Calculate the modular inverse of the determinant
    for (int i = 0; i < 4; i++) {
        inverse_key[i] = (inverse_key[i] * inverse) % MOD;
    }

    // Decrypt the ciphertext
    int plaintext[2];
    plaintext[0] = (inverse_key[0] * ciphertext[0] + inverse_key[1] * ciphertext[1]) % MOD;
    plaintext[1] = (inverse_key[2] * ciphertext[0] + inverse_key[3] * ciphertext[1]) % MOD;

    // Print the decrypted plaintext
    printf("Decrypted Plaintext: %c%c\n", plaintext[0] + 'A', plaintext[1] + 'A');
}

int main() {
    // Known plaintext-ciphertext pair
    int ciphertext[2] = {3, 19}; // Corresponding to "DS"

    // Corresponding known plaintext (in uppercase)
    int known_plaintext[2] = {3, 18}; // Corresponding to "DR"

    // Calculate the key matrix
    int key[4];
    key[0] = (ciphertext[0] - known_plaintext[0] + MOD) % MOD;
    key[1] = (ciphertext[1] - known_plaintext[1] + MOD) % MOD;
    key[2] = (ciphertext[0] - known_plaintext[0] + MOD) % MOD;
    key[3] = (ciphertext[1] - known_plaintext[1] + MOD) % MOD;

    // Print the key matrix
    printf("Key Matrix:\n");
    printf("%d %d\n", key[0], key[1]);
    printf("%d %d\n", key[2], key[3]);

    // Decrypt using the calculated key matrix
    decrypt_hill(ciphertext, key);

    return 0;
}

