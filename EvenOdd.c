#include<stdio.h>
#include<conio.h>

int main()
{
	clrscr();
	int i;
	int arr[5];
	int even=0;
	int odd=0;

	printf("Enter The Number:\n");
	for(i=0; i<5; i++)
	{
		scanf("%d",&arr[i]);
	}
	for(i=0; i<5; i++)
	{
		if(arr[i]%2==0)
		{
			even++;
		}
		else
		{
			odd++;
		}
	}
	printf("Even Number Is: %d\n",even);
	printf("Odd Number Is: %d\n",odd);
	getch();
	return 0;
}
