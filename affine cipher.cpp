#include <stdio.h>

int gcd(int a, int b) {
    if (b == 0)
        return a;
    else
        return gcd(b, a % b);
}
int modInverse(int a, int m) {
    for (int x = 1; x < m; x++)
        if ((a * x) % m == 1)
            return x;
    return -1;
}
void decryptAffineCipher(char ciphertext[], int a, int b) {
    int m = 26;
    int aInverse = modInverse(a, m);

    if (aInverse == -1) {
        printf("Invalid key. Decryption is not possible.\n");
        return;
    }
    for (int i = 0; ciphertext[i] != '\0'; i++) {
        if (ciphertext[i] != ' ')
            printf("%c", (aInverse * (ciphertext[i] - 'A' - b + m) % m + m) % m + 'A');
        else
            printf(" ");
    }
    printf("\n");
}
int main() {
    char ciphertext[] = "BUUBU BUUBU BBUBBUBUBUBU";
    int mostFrequent = 'B' - 'A';
    int secondMostFrequent = 'U' - 'A';

    for (int a = 1; a < 26; a++)
        if (gcd(a, 26) == 1)
            printf("Trying a=%d, b=%d: ", a, (mostFrequent - a * secondMostFrequent + 26) % 26), decryptAffineCipher(ciphertext, a, (mostFrequent - a * secondMostFrequent + 26) % 26);

    return 0;
}
