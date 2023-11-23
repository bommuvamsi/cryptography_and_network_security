#include <stdio.h>
#include <stdint.h>

// Permutation choice 1 table
const int PC1[] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

// Permutation choice 2 table
const int PC2[] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

// Key schedule shifts
const int keyScheduleShifts[] = {
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1
};

// Permutation of the 56-bit key for the first and second 24 bits
void permutationChoice1(uint64_t *key, uint64_t *left, uint64_t *right) {
    *left = *right = 0;

    for (int i = 0; i < 56; i++) {
        uint64_t bit = (*key >> (64 - PC1[i])) & 1;

        if (i < 28) {
            *left <<= 1;
            *left |= bit;
        } else {
            *right <<= 1;
            *right |= bit;
        }
    }
}

// Key schedule generation with disjoint subsets
void generateRoundKeys(uint64_t *key, uint64_t *roundKeys) {
    uint64_t left, right;
    permutationChoice1(key, &left, &right);

    for (int round = 0; round < 16; round++) {
        // Perform key schedule shifts
        left = (left << keyScheduleShifts[round]) | (left >> (28 - keyScheduleShifts[round]));
        right = (right << keyScheduleShifts[round]) | (right >> (28 - keyScheduleShifts[round]));

        // Combine the two halves
        uint64_t combinedKey = (left << 28) | right;

        // Perform permutation choice 2 to generate the round key
        uint64_t roundKey = 0;
        for (int i = 0; i < 48; i++) {
            uint64_t bit = (combinedKey >> (56 - PC2[i])) & 1;
            roundKey = (roundKey << 1) | bit;
        }

        // Save the round key
        roundKeys[round] = roundKey;
    }
}

int main() {
    // Example usage
    uint64_t key = 0x133457799BBCDFF1; // Replace with your key

    // Generate round keys
    uint64_t roundKeys[16];
    generateRoundKeys(&key, roundKeys);

    // Display the generated round keys
    for (int round = 0; round < 16; round++) {
        printf("Round %d Key: %llx\n", round + 1, roundKeys[round]);
    }

    return 0;
}

