#include<stdio.h>
#include<string.h>
int main()
{
	int r1,r2,c1,c2,k[20][20],i,j,f;
	char a[20][20],g[20][20];
	int b[20][20],c[20][20],s[20][20],len,l;
	printf("Enter number of rows in key matrix: ");
	scanf("%d",&r1);
	printf("\nEnter number of columns in key matrix: ");
	scanf("%d",&c1);
	printf("\nkey matrix: ");
	for(i=0;i<r1;i++)
	{
		for(j=0;j<c1;j++)
		{
			scanf("%d",&k[i][j]);
		}
	}
	printf("\nEnter no.of rows of the plain text: ");
	scanf("%d",&r2);
		printf("\Enter no.of columns of the plain text: ");
			scanf("%d",&c2);
	printf("\nthe plain text into cipher text\n");
	for(i=0;i<r2;i++)
	{
		for(j=0;j<c2;j++)
		{
	        scanf("\n%c",&a[i][j]);
	        b[i][j]=a[i][j]-'a';
		    printf("\n%d",b[i][j]);
		}
	}
	printf("\nthe numeric text");
	for(i=0;i<r2;i++)
	{
		for(j=0;j<c2;j++)
		{
		    printf("\n%d",b[i][j]);
		}
	}
	printf("\nthe multiplication of the key with the numeric values");
	for(i=0;i<r1;i++)
	{
		for(j=0;j<c2;j++)
		{
			c[i][j]=0;
			for(l=0;l<c1;l++)
			{
				c[i][j]+=k[i][l]*b[l][j];
			}
		}
	}
	printf("\nthe multiplication of the values");
	for(i=0;i<r1;i++)
	{
		for(j=0;j<c2;j++)
		{
			printf("\n%d",c[i][j]);
		}
	}
	printf("\nthe cipher text in numeric format");
	for(i=0;i<r1;i++)
	{
		for(j=0;j<c2;j++)
		{
			s[i][j]=c[i][j]%26;
			printf("\n%d",s[i][j]);
		}
	}
	printf("the cipher text in aplhabets");
	for(i=0;i<r1;i++)
	{
		for(j=0;j<c2;j++)
		{
			if(s[i][j]>=0&&s[i][j]<=25)
			g[i][j]='a'+s[i][j];
			printf("\n%c",g[i][j]);
		}
	}
}
