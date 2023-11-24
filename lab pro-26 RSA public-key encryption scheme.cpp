#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// Function to calculate the greatest common divisor (GCD) of two numbers
int gcd(int a, int b) {
    if (b == 0) {
        return a;
    } else {
        return gcd(b, a % b);
    }
}

// Function to calculate the modular inverse using extended Euclidean algorithm
int mod_inverse(int a, int m) {
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;

    if (m == 1) {
        return 0;
    }

    // Apply extended Euclidean algorithm
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    // Make x1 positive
    if (x1 < 0) {
        x1 += m0;
    }

    return x1;
}

// Function to perform RSA key generation
void generate_keys(int *e, int *d, int *n) {
    // Choose two distinct prime numbers
    int p = 61;
    int q = 53;

    *n = p * q; // Compute modulus n
    int phi = (p - 1) * (q - 1); // Compute Euler's totient function

    // Choose public key e such that 1 < e < phi and gcd(e, phi) = 1
    *e = 17;

    // Compute private key d such that d * e = 1 (mod phi)
    *d = mod_inverse(*e, phi);
}

// Function to perform RSA encryption
int encrypt(int plaintext, int e, int n) {
    // Ciphertext = (plaintext^e) mod n
    int ciphertext = 1;
    for (int i = 0; i < e; i++) {
        ciphertext = (ciphertext * plaintext) % n;
    }
    return ciphertext;
}

// Function to perform RSA decryption
int decrypt(int ciphertext, int d, int n) {
    // Plaintext = (ciphertext^d) mod n
    int plaintext = 1;
    for (int i = 0; i < d; i++) {
        plaintext = (plaintext * ciphertext) % n;
    }
    return plaintext;
}

int main() {
    int e, d, n;

    // Generate RSA keys
    generate_keys(&e, &d, &n);
    printf("Public Key (e, n): (%d, %d)\n", e, n);
    printf("Private Key (d, n): (%d, %d)\n", d, n);

    // Original message
    int plaintext = 42;
    printf("Original Message: %d\n", plaintext);

    // Encrypt the message
    int ciphertext = encrypt(plaintext, e, n);
    printf("Encrypted Message: %d\n", ciphertext);

    // Decrypt the message
    int decrypted_message = decrypt(ciphertext, d, n);
    printf("Decrypted Message: %d\n", decrypted_message);

    return 0;
}

