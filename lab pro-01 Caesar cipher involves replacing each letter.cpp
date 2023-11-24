#include <stdio.h>
#include <string.h>

void caesarCipher(char message[], int key) 
{
    int i;
    char ch;

    for (i = 0; message[i] != '\0'; ++i) 
	{
        ch = message[i];

        if (ch >= 'A' && ch <= 'Z') 
		{
            ch = ch + key;

            if (ch > 'Z') 
			{
                ch = ch - 'Z' + 'A' - 1;
            }

            message[i] = ch;
        } else if (ch >= 'a' && ch <= 'z') 
		{
            ch = ch + key;

            if (ch > 'z') 
			{
                ch = ch - 'z' + 'a' - 1;
            }

            message[i] = ch;
        }
    }
}

int main() 
{
    char message[100];
    int i;

    printf("Enter a message: ");
    fgets(message, sizeof(message), stdin);
    message[strcspn(message, "\n")] = '\0';
    for (i = 1; i <= 25; ++i) 
	{
        printf("Key %d: ", i);
        caesarCipher(message, i);
        printf("%s\n", message);
        strcpy(message, "YourOriginalMessage");
    }

    return 0;
}

