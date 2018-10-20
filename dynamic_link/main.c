#include <stdio.h>

int add(int a, int b);
int sub(int a, int b);

void main()
{
	int c;
	extern int sum;

	c = add(1,2);
	sum = add(c, 1);
	sum = sub(sum, 1);

	printf("sum = %d\n", sum);

	getchar();
	return;
}
