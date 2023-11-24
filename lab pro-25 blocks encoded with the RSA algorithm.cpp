#include <stdio.h>
#include <math.h>
int gcd (int a,int b)
{
	if(b==0)
	return a;
	return gcd(b, a%b);
}
int main()
{
	int p,q,n,n1,d,e,C,P,M;
	printf("enter first prime number p: ");
	scanf("%d",&p);
	printf("\nenter second prime number q: ");
	scanf("%d",&q);
	n=p*q;
	printf("\nthe n value is %d",n);
	n1=(p-1)*(q-1);
	printf("\nthe n1 value is %d",n1);
	for(e=2;e<n1;e++)
	{
    if(gcd(e,n1)==1)
    {
	printf("\nthe e value is %d",e);
	break;
}
}
for(d=2;d<n1;d++)
	{
	if(e*d%n1==1)
	{
	printf("\nthe d value is %d",d);
	break;
}
}
	printf("\nEnter M value: ");
	scanf("%d",&M);
	C=fmod(pow(M,e),n);
	printf("\nthe cipher text value is %d",C);
	P=fmod(pow(C,d),n);
	printf("\nthe plain text value is %d",P);
}
