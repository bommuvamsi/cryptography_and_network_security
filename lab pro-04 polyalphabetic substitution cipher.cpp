#include <stdio.h>
#include <string.h>
#include <ctype.h>

void encryptVigenere(char message[], char key[]) 
{
    int i, j;
    int messageLen = strlen(message);
    int keyLen = strlen(key);

    for (i = 0, j = 0; i < messageLen; ++i) 
	{
        if (isalpha(message[i])) 
		{
            char caseOffset = isupper(message[i]) ? 'A' : 'a';
            char keyChar = key[j % keyLen];
            char keyOffset = isupper(keyChar) ? 'A' : 'a';
            message[i] = ((message[i] - caseOffset + keyChar - keyOffset) % 26) + caseOffset;

            ++j;
        }
    }
}

int main() 
{
    char message[100];
    char key[100]; 
    int i;

    printf("Enter a message: ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = '\0';

    printf("Enter the key: ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';
    encryptVigenere(message, key);
    printf("Encrypted Message: %s\n", message);

    return 0;
}

