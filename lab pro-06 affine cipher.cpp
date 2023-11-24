#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main() 
{
    int k, i;
    char s[100], c[100];

    printf("Enter key value: ");
    scanf("%d", &k);

    printf("Enter plain text: ");
    scanf("%s", s);

    printf("The encryption is: ");
    for (i = 0; i < strlen(s); i++) 
	{
        if (islower(s[i])) {
            c[i] = (char)(((s[i] - 'a' + k) % 26) + 'a');
        } else if (isdigit(s[i])) 
		{
            c[i] = (char)(((s[i] - '0' + k) % 10) + '0');
        } else if (isupper(s[i])) 
		{
            c[i] = (char)(((s[i] - 'A' + k) % 26) + 'A');
        } else {
            c[i] = s[i];
        }
        printf("%c", c[i]);
    }
    printf("\n");

    printf("The decryption is: ");
    for (i = 0; i < strlen(s); i++) 
	{
        if (islower(c[i])) 
		{
            s[i] = (char)(((c[i] - 'a' - k + 26) % 26) + 'a');
        } else if (isdigit(c[i])) 
		{
            int h, f;
            h = c[i] - '0' - k;
            if (h < 0) {
                f = h + 10;
                s[i] = (char)((f % 10) + '0');
            } else {
                s[i] = (char)(((c[i] - '0' - k) % 10) + '0');
            }
        } else if (isupper(c[i])) 
		{
            s[i] = (char)(((c[i] - 'A' - k + 26) % 26) + 'A');
        } else {
            s[i] = c[i]; 
        }
        printf("%c", s[i]);
    }

    return 0;
}

