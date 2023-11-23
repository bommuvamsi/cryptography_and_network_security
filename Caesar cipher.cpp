#include <stdio.h>
#include <string.h>

void encrypt(char message[], int shift);

int main() {
    char message[100];
    

    printf("Enter a message to encrypt: ");
    fgets(message, sizeof(message), stdin);
    
    for (int shift = 1; shift <= 25; ++shift) {
        printf("Shift %d: ", shift);
        encrypt(message, shift);
    }

    return 0;
}

void encrypt(char message[], int shift) {
    int length = strlen(message);

    for (int i = 0; i < length; ++i) {
        char ch = message[i];

        if (ch >= 'A' && ch <= 'Z') {
          
            ch = (ch - 'A' + shift) % 26 + 'A';
        } else if (ch >= 'a' && ch <= 'z') {
        
            ch = (ch - 'a' + shift) % 26 + 'a';
        }

        printf("%c", ch);
    }

    printf("\n");
}

