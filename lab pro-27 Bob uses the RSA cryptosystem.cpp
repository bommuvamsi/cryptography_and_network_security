#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Function to calculate the modular exponentiation (a^b mod n)
long long mod_pow(long long base, long long exponent, long long modulus) {
    long long result = 1;
    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }
    return result;
}

int main() {
    // Bob's public key (e, n)
    long long e = 65537;
    long long n = 10000000000000000019LL;  // A large prime modulus

    // Message to be encrypted (each letter represented as an integer)
    int plaintext[] = {0, 2, 4, 8, 12, 14, 18, 24};

    // Encrypt each letter separately
    for (int i = 0; i < sizeof(plaintext) / sizeof(plaintext[0]); ++i) {
        long long encrypted_char = mod_pow(plaintext[i], e, n);
        printf("%lld ", encrypted_char);
    }

    return 0;
}

