
* Buffer Overflow(Bof)
  1. C/C++ Compiler가 array의 boundary check를 수행하지 않아 선언된 array의 size보다 더 큰 data를 write하게 됨으로써 발생되는 현상
  2. OS가 stack 또는 heap 영역에 대해 임의의 데이터를 write 하거나 execute를 허용함으로써 발생되는 현상

* Buffer Overflow 종류
  1. Stack-Based Buffer Overflow
     - stack 영역에 할당된 buffer에 buffer의 size를 초과하는 data(실행 가능 코드 - shellcode)를 write하고 저장된 return address를 변경하여 임의의 code를 실행하는 방식
       ("Smashing The Stack For Fun And Profit", Aleph One, Phrack 49-14)

  2. Heap-Based Buffer Overflow
     - 인접한 주소에 할당된 낮은 주소에 위치한 buffer를 overflow 시켜 data나 function pointer를 변경함으로써 임의의 파일에 접근하거나 임의의 코드를 실행
       ("wOOwOO on Heap Overflows", wOOwOO)

* Memory Space
---------------------------
program code
---------------------------
Data(전역변수)
---------------------------
Heap (by malloc())
---------------------------
                    ↓


                    ↑
---------------------------
Stack(함수파라미터, 리턴주소)
---------------------------

* Buffer Overflow 취약점을 이용한 공격방법
  1. 공격 대상
     - Buffer Overflow 취약점이 존재하는 server daemon 또는 system management program
     - 주로 root 권한을 가지고 있거나, setuid bit가 걸려있는 program

  2. 공격 절차
     1) 취약점 탐지 및 정보수집
        - OS, Program, Version, etc
        - Exploit code from the well-know security portal sites
     2) Exploit program 작성
        - local 및 remote 공격용 shell code 작성


** Stack Overflow 공격

ex) bof_example.c

#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[])
{
        char buffer[8];

        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);

        return 0;
}


guybrush@nt900x5t:~/Project/github/hack/binhacks/buffer_overflow$ gcc -o bof_example bof_example.c -m32 -fno-stack-protector -mpreferred-stack-boundary=2 -g
guybrush@nt900x5t:~/Project/github/hack/binhacks/buffer_overflow$ ./bof_example $(perl -e 'print "A"x7')
AAAAAAA
guybrush@nt900x5t:~/Project/github/hack/binhacks/buffer_overflow$ ./bof_example $(perl -e 'print "A"x11')
AAAAAAAAAAA
guybrush@nt900x5t:~/Project/github/hack/binhacks/buffer_overflow$ ./bof_example $(perl -e 'print "A"x12')
AAAAAAAAAAAA
Segmentation fault (core dumped)
guybrush@nt900x5t:~/Project/github/hack/binhacks/buffer_overflow$

* ./bof_example $(perl -e 'print "A"x7') == ./bof_example AAAAAAA


Why bof_example is crashed?


1. A 문자 7개를 입력값으로 넣고, 지역변수 buffer 할당완료 코드까지 실행시킨 후 stack pointer 값을 확인해보자.

guybrush@nt900x5t:~/Project/github/hack/binhacks/buffer_overflow$ gdb -q ./bof_example
Reading symbols from ./bof_example...done.
(gdb) l
1	#include <stdio.h>
2	#include <string.h>
3
4	int main(int argc, char* argv[])
5	{
6		char buffer[8];
7
8		strcpy(buffer, argv[1]);
9		printf("%s\n", buffer);
10
(gdb) b 8
Breakpoint 1 at 0x8048441: file bof_example.c, line 8.
(gdb) r $(perl -e 'print "A"x7')
Starting program: /home/guybrush/Project/github/hack/binhacks/buffer_overflow/bof_example $(perl -e 'print "A"x7')


Breakpoint 1, main (argc=2, argv=0xffffce74) at bof_example.c:8
8		strcpy(buffer, argv[1]);
(gdb) p &buffer
$1 = (char (*)[8]) 0xffffcdd0
(gdb) i r $esp
esp            0xffffcdd0	0xffffcdd0
(gdb) i r $ebp
ebp            0xffffcdd8	0xffffcdd8

(gdb) disassemble
Dump of assembler code for function main:
   0x0804843b <+0>:	push   ebp
   0x0804843c <+1>:	mov    ebp,esp
   0x0804843e <+3>:	sub    esp,0x8
=> 0x08048441 <+6>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048444 <+9>:	add    eax,0x4
   0x08048447 <+12>:	mov    eax,DWORD PTR [eax]
   0x08048449 <+14>:	push   eax
   0x0804844a <+15>:	lea    eax,[ebp-0x8]
   0x0804844d <+18>:	push   eax
   0x0804844e <+19>:	call   0x8048300 <strcpy@plt>
   0x08048453 <+24>:	add    esp,0x8
   0x08048456 <+27>:	lea    eax,[ebp-0x8]
   0x08048459 <+30>:	push   eax
   0x0804845a <+31>:	call   0x8048310 <puts@plt>
   0x0804845f <+36>:	add    esp,0x4
   0x08048462 <+39>:	mov    eax,0x0
   0x08048467 <+44>:	leave
   0x08048468 <+45>:	ret
End of assembler dump.

=> 아직 strcpy() 코드는 수행전이므로, stack에 buffer[8]만 할당되어 있는 상태이며, buffer와 stack pointer 값은 동일하다.
   ebp로 부터 buffer size 만큼 esp가 이동한 상태



(gdb) x/8wx $esp
0xffffcdd0:	0xf7fb5000(buffer[0] ~ [3])	0xf7fb5000(buffer[4] ~ [7])	0x00000000(old ebp)	0xf7e1d637(return address)
0xffffcde0:	0x00000002(argc)	        0xffffce74	                0xffffce80		0x00000000

=> 현재 stack pointer로부터 8개의 word byte를 확인해 보면, 위와 같다.
   stack 주소는 address상 높은 번지에서 낮은 번지로 이동하므로(system마다 다름), 위의 출력결과는 이전에 stack에 쌓여져 있는 정보들을 보여준다.


(gdb) p buffer
$2 = "\000P\373\367\000P\373", <incomplete sequence \367>

=> buffer에는 초기화 되지 않은 쓰레기값이 들어가 있는 상태

(gdb) n
9		printf("%s\n", buffer);
(gdb) p buffer
$3 = "AAAAAAA"

=> strcpy()가 수행되면서, buffer에 입력값 A 7개가 저장되었다.

(gdb) x/8wx $esp
0xffffcdd0:	0x41414141(buffer[0] ~ [3])	0x00414141(buffer[4] ~ [7])	0x00000000	0xf7e1d637
0xffffcde0:	0x00000002			0xffffce74			0xffffce80	0x00000000

=> 다시 stack pointer 로부터 8개의 word byte를 확인해보니, stack에 할당된 buffer 변수의 위치에 A(0x41) 가 7개 저장되어 있고,
   마지막 null(0x00)까지 8 bytes가 저장되어 있음을 확인할 수 있다.


=> 이번에는 strcpy() 코드 수행 후 위치를 break point로 잡고, A 입력값을 11개로 더 늘려보자.

(gdb) d 1
(gdb) l
4	int main(int argc, char* argv[])
5	{
6		char buffer[8];
7
8		strcpy(buffer, argv[1]);
9		printf("%s\n", buffer);
10
11		return 0;
12	}
(gdb) b 9
Breakpoint 2 at 0x8048456: file bof_example.c, line 9.
(gdb) r $(perl -e 'print "A"x11')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/guybrush/Project/github/hack/binhacks/buffer_overflow/bof_example $(perl -e 'print "A"x11')

Breakpoint 2, main (argc=2, argv=0xffffce74) at bof_example.c:9
9		printf("%s\n", buffer);
(gdb) x/8wx $esp
0xffffcdd0:	0x41414141(buffer[0] ~ [3])	0x41414141(buffer[4] ~ [7])	0x00414141(old ebp)	0xf7e1d637(return address)
0xffffcde0:	0x00000002			0xffffce74			0xffffce80		0x00000000

=> 이번에는 buffer 뿐만 아니라, old ebp를 저장하고 있는 위치까지 A(0x41)값이 써져 있는 것을 확인할 수 있다.
   Ax11 + null 까지 총 12bytes가 stack에 써지면서, buffer 8 bytes 다음 위치인 old ebp 값까지 overwrite 되었다.


(gdb) r $(perl -e 'print "A"x12')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/guybrush/Project/github/hack/binhacks/buffer_overflow/bof_example $(perl -e 'print "A"x12')

Breakpoint 2, main (argc=2, argv=0xffffce74) at bof_example.c:9
9		printf("%s\n", buffer);
(gdb) x/8wx $esp
0xffffcdd0:	0x41414141(buffer[0] ~ [3])	0x41414141(buffer[4] ~ [7])	0x41414141(old ebp)	0xf7e1d600(return address)
0xffffcde0:	0x00000002			0xffffce74			0xffffce80		0x00000000

=> A값을 12개까지 입력하면, null까지 총 13 bytes가 입력되면서, old ebp 값뿐만 아니라 return address 값 까지 변경되었다.
   기존 return address 값 0xf7e1d637 => 0xf7e1d600으로 마지막 byte에 null이 overwrite 되면서, 결국 return address의 주소가 변경되는 결과가 발생

(gdb) c
Continuing.
AAAAAAAAAAAA

Program received signal SIGSEGV, Segmentation fault.
0xf7e1d600 in __libc_start_main () from /lib32/libc.so.6
(gdb)

=> 이어서 실행을 해보면, return address가 기존 0xf7e1d637에서 알수없는 주소인 0xf7e1d600으로 변경되면서 segmentation fault가 발생하게 된다.






(gdb) b *main
Breakpoint 3 at 0x804843b: file bof_example.c, line 5.
(gdb) r
Starting program: /home/guybrush/Project/github/hack/binhacks/buffer_overflow/bof_example $(perl -e 'print "A"x12')

Breakpoint 3, main (argc=2, argv=0xffffce74) at bof_example.c:5
5	{
(gdb) r $(perl -e 'print "A"x7')
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /home/guybrush/Project/github/hack/binhacks/buffer_overflow/bof_example $(perl -e 'print "A"x7')

Breakpoint 3, main (argc=2, argv=0xffffce74) at bof_example.c:5
5	{
(gdb) disassemble
Dump of assembler code for function main:
=> 0x0804843b <+0>:	push   ebp
   0x0804843c <+1>:	mov    ebp,esp
   0x0804843e <+3>:	sub    esp,0x8
   0x08048441 <+6>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048444 <+9>:	add    eax,0x4
   0x08048447 <+12>:	mov    eax,DWORD PTR [eax]
   0x08048449 <+14>:	push   eax
   0x0804844a <+15>:	lea    eax,[ebp-0x8]
   0x0804844d <+18>:	push   eax
   0x0804844e <+19>:	call   0x8048300 <strcpy@plt>
   0x08048453 <+24>:	add    esp,0x8
   0x08048456 <+27>:	lea    eax,[ebp-0x8]
   0x08048459 <+30>:	push   eax
   0x0804845a <+31>:	call   0x8048310 <puts@plt>
   0x0804845f <+36>:	add    esp,0x4
   0x08048462 <+39>:	mov    eax,0x0
   0x08048467 <+44>:	leave
   0x08048468 <+45>:	ret
End of assembler dump.
(gdb) i r
eax            0xf7fb6dbc	-134517316
ecx            0x5292c47d	1385350269
edx            0xffffce04	-12796
ebx            0x0	0
esp            0xffffcddc	0xffffcddc
ebp            0x0	0x0
esi            0xf7fb5000	-134524928
edi            0xf7fb5000	-134524928
eip            0x804843b	0x804843b <main>
eflags         0x292	[ AF SF IF ]
cs             0x23	35
ss             0x2b	43
ds             0x2b	43
es             0x2b	43
fs             0x0	0
gs             0x63	99
(gdb) x/x $esp
0xffffcddc:	0xf7e1d637
(gdb) x/4wx
0xffffcde0:	0x00000002	0xffffce74	0xffffce80	0x00000000
(gdb) x/4wx $esp
0xffffcddc:	0xf7e1d637	0x00000002	0xffffce74	0xffffce80
(gdb) x/x$ebp
0x0:	Cannot access memory at address 0x0
(gdb) x/x $ebp
0x0:	Cannot access memory at address 0x0
(gdb) p argc
$4 = 2
(gdb) p &argc
$5 = (int *) 0xffffcde0
(gdb) x/x $esp+0x4
0xffffcde0:	0x00000002
(gdb) p &argv
$6 = (char ***) 0xffffcde4
(gdb) p argv
$7 = (char **) 0xffffce74
(gdb) p *argv
$8 = 0xffffd07d "/home/guybrush/Project/github/hack/binhacks/buffer_overflow/bof_example"
(gdb) x/s 0xffffce74
0xffffce74:	"}\320\377\377\305\320\377\377"
(gdb) x/x 0xffffce74
0xffffce74:	0x7d
(gdb) x/4x 0xffffce74
0xffffce74:	0x7d	0xd0	0xff	0xff
(gdb) x/s 0xffffd07d
0xffffd07d:	"/home/guybrush/Project/github/hack/binhacks/buffer_overflow/bof_example"
(gdb) p &argv[0]
$9 = (char **) 0xffffce74
(gdb) p argv[0]
$10 = 0xffffd07d "/home/guybrush/Project/github/hack/binhacks/buffer_overflow/bof_example"
(gdb) p &argv[1]
$11 = (char **) 0xffffce78
(gdb) p argv[1]
$12 = 0xffffd0c5 "AAAAAAA"
(gdb) x/x 0xffffce80
0xffffce80:	0xcd
(gdb) x/4x 0xffffce80
0xffffce80:	0xcd	0xd0	0xff	0xff
(gdb) x/s 0xffffd0cd
0xffffd0cd:	"LC_PAPER=ko_KR.UTF-8"
(gdb)


(gdb) x/x 0xffffce80
0xffffce80:	0xcd

(gdb) x/4x 0xffffce80
0xffffce80:	0xcd	0xd0	0xff	0xff

(gdb) x/wx 0xffffce80
0xffffce80:	0xffffd0cd

(gdb) x/s 0xffffd0cd
0xffffd0cd:	"LC_PAPER=ko_KR.UTF-8"

(gdb) x/s *0xffffce80
0xffffd0cd:	"LC_PAPER=ko_KR.UTF-8"

(gdb) x/4s *0xffffce80
0xffffd0cd:	"LC_PAPER=ko_KR.UTF-8"
0xffffd0e2:	"XDG_VTNR=7"
0xffffd0ed:	"XDG_SESSION_ID=c2"
0xffffd0ff:	"LC_ADDRESS=ko_KR.UTF-8"

(gdb) x/10s *0xffffce80
0xffffd0cd:	"LC_PAPER=ko_KR.UTF-8"
0xffffd0e2:	"XDG_VTNR=7"
0xffffd0ed:	"XDG_SESSION_ID=c2"
0xffffd0ff:	"LC_ADDRESS=ko_KR.UTF-8"
0xffffd116:	"CLUTTER_IM_MODULE=xim"
0xffffd12c:	"LC_MONETARY=ko_KR.UTF-8"
0xffffd144:	"XDG_GREETER_DATA_DIR=/var/lib/lightdm-data/guybrush"
0xffffd178:	"GPG_AGENT_INFO=/home/guybrush/.gnupg/S.gpg-agent:0:1"
0xffffd1ad:	"SHELL=/bin/bash"
0xffffd1bd:	"VTE_VERSION=4205"





"AAAAAAA"	*argv[1]								0xffffd0c5
----------------------------------
"/home/guybrush/Project/github/hack/binhacks/buffer_overflow/bof_example"	*argv[0] 0xffffd07d
----------------------------------

......

----------------------------------
					0xffffce80
----------------------------------
					0xffffce7c
----------------------------------
0xffffd0c5 (argv[1])		   0xffffce78 (argv[1] 주소)
----------------------------------
0xffffd07d (argv[0])		   0xffffce74 (argv[0] 주소)
----------------------------------
----------------------------------
----------------------------------
0xffffce80
----------------------------------
0xffffce74 (argv)
----------------------------------
0x00000002 (argc)
----------------------------------
0xf7e1d637 (return address)	   0xffffcddc (esp)
----------------------------------
----------------------------------


















