#include<stdio.h>
#include<string.h>
#include<ctype.h>
int main()
{
	int k,i;
	char s[100],c[100];
	printf("enter plain text: ");
	scanf("%s",&s);
	printf("enter key: ");
	scanf("%d",&k);
	printf("\nEncryption: ");
	for(i=0;i<strlen(s);i++)
	{
		if(islower(s[i]))
		{
			c[i]=((s[i]-'a'+k)%26)+'a';
		}
		else
		{
			c[i]=((s[i]-'A'+k)%26)+'A';
		}
		printf("%c",c[i]);
	}
	printf("\nDecryption: ");
	for(i=0;i<strlen(s);i++)
	{
		if(islower(c[i]))
		{
			s[i]=(((c[i]-'a'-k)+26)%26)+'a';
		}
		else
		{
			s[i]=(((c[i]-'A'-k)+26)%26)+'A';
		}
		printf("%c",s[i]);
	}
}
