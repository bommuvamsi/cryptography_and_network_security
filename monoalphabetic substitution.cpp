#include <stdio.h>
#include <string.h>

void encrypt(char message[], char key[]);

int main() {
    char message[100];
    char key[26];

    printf("Enter a message to encrypt: ");
    fgets(message, sizeof(message), stdin);

    printf("Enter the substitution key (26 unique letters): ");
    fgets(key, sizeof(key), stdin);

    if (strlen(key) != 27) {
        printf("Invalid key. Please enter 26 unique letters.\n");
        return 1;
    }

    encrypt(message, key);

    return 0;
}

void encrypt(char message[], char key[]) {
    int length = strlen(message);

    for (int i = 0; i < length; ++i) {
        char ch = message[i];

        if (ch >= 'A' && ch <= 'Z') {
           
            printf("%c", key[ch - 'A']);
        } else if (ch >= 'a' && ch <= 'z') {
           
            printf("%c", key[ch - 'a'] + 'a' - 'A');
        } else {
            
            printf("%c", ch);
        }
    }

    printf("\n");
}

