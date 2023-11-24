#include <stdio.h>
#include <math.h>
#include <ctype.h>
#include <string.h>
int main()
{
	int k,i;
	char s[100],c[100];
	printf("enter the plain text: ");
	scanf("%s",&s);
	printf("\nenter the key value: ");
	scanf("%d",&k);
	printf("\nencryption: ");
	for(i=0;i<strlen(s);i++)
	{
		if(islower(s[i]))
		{
			c[i]=((s[i]-'a'+k)%26)+'a';
				printf("%c",c[i]);
		}
		else
		{
			c[i]=((s[i]-'A'+k)%26)+'A';
				printf("%c",c[i]);
			}	
				}
		printf("\ndecryption: ");
	for(i=0;i<strlen(s);i++)
	{
		if(islower(c[i]))
		{
			s[i]=((c[i]-'a'-k)+26)%26+'a';
			printf("%c",s[i]);
		}
		else
		{
			s[i]=((c[i]-'A'-k)+26)%26+'A';
			printf("%c",s[i]);
		}
	}
	return 0;
}
