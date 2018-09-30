#include <stdio.h>

void func();

int sum;

int main() {
	int var1;
	int *var2 = &var1;

	var1 = 1;

	sum = var1 + *var2;

	func();

	printf("sum = %d\n", sum);

	return 0;
}
