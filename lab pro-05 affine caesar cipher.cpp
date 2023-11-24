#include <stdio.h>
#include <ctype.h>
int modInverse(int a, int m) 
{
    int m0 = m, t, q;
    int x0 = 0, x1 = 1;

    if (m == 1)
        return 0;
    while (a > 1) 
	{
        q = a / m;
        t = m;
        m = a % m, a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0)
        x1 += m0;

    return x1;
}
char encryptAffineCipher(char ch, int a, int b) 
{
    if (isalpha(ch)) 
	{
        char case_offset = isupper(ch) ? 'A' : 'a';
        return (char)(((a * (ch - case_offset) + b) % 26) + case_offset);
    } else 
	{
        return ch;
    }
}
int hasInverse(int a) 
{
    return (a % 2 != 0) && (a % 13 != 0);
}

int main() 
{
    int a, b;
    char message[100];
    printf("Enter the value of a (must be coprime with 26): ");
    scanf("%d", &a);

    if (!hasInverse(a)) 
	{
        printf("Error: 'a' must be coprime with 26 for a modular inverse to exist.\n");
        return 1;
    }

    printf("Enter the value of b: ");
    scanf("%d", &b);
    printf("Enter a message: ");
    scanf(" %[^\n]s", message);
    for (int i = 0; message[i] != '\0'; ++i) 
	{
        message[i] = encryptAffineCipher(message[i], a, b);
    }
    printf("Encrypted Message: %s\n", message);

    return 0;
}

