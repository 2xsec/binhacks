#include <stdlib.h>
#include <string.h>

char *arr = "SEC";
char *arr2;
char *cp;

void func()
{
	int var3;

	arr2 = (char *)malloc(10);

	strncpy(arr2, "2XSEC", 9);

	cp = arr + 2;
	var3 = 32;

	return;
}
