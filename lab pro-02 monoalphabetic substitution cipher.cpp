#include <stdio.h>
#include <string.h>
#include <ctype.h>

void encryptMonoalphabetic(char message[], char key[]) {
    int i;

    for (i = 0; message[i] != '\0'; ++i) {
        if (isalpha(message[i])) {
            char case_offset = isupper(message[i]) ? 'A' : 'a';

            message[i] = key[message[i] - case_offset];
        }
    }
}

int main() {
    char message[100];
    char key[27]; 
    int i;

    printf("Enter a message: ");
    fgets(message, sizeof(message), stdin);

    message[strcspn(message, "\n")] = '\0';

    printf("Enter the substitution key (26 unique letters): ");
    fgets(key, sizeof(key), stdin);

    key[strcspn(key, "\n")] = '\0';

    if (strlen(key) != 26) {
        printf("Error: The key must be 26 characters long.\n");
        return 1; 
    }

    encryptMonoalphabetic(message, key);

    printf("Encrypted Message: %s\n", message);

    return 0;
}

