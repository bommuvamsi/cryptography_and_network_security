#include <stdio.h>
#include <stdlib.h>
#include <math.h>
long long mod_pow(long long base, long long exponent, long long modulus) 
{
    long long result = 1;
    while (exponent > 0) 
	{
        if (exponent % 2 == 1) 
		{
            result = (result * base) % modulus;
        }
        base = (base * base) % modulus;
        exponent /= 2;
    }
    return result;
}

long long diffie_hellman(long long base, long long private_key, long long modulus) 
{
    return mod_pow(base, private_key, modulus);
}

int main() 
{
    long long base = 5; 
    long long modulus = 23;  

    long long alice_private_key = 6;
    long long bob_private_key = 15;
    long long alice_public_value = diffie_hellman(base, alice_private_key, modulus);
    long long bob_public_value = diffie_hellman(base, bob_private_key, modulus);

    printf("Alice sends: %lld\n", alice_public_value);
    printf("Bob sends: %lld\n", bob_public_value);

    long long alice_shared_secret = diffie_hellman(bob_public_value, alice_private_key, modulus);
    long long bob_shared_secret = diffie_hellman(alice_public_value, bob_private_key, modulus);

    printf("Shared secret for Alice: %lld\n", alice_shared_secret);
    printf("Shared secret for Bob: %lld\n", bob_shared_secret);

    return 0;
}

