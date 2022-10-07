# Shellcode Development

## Introduction

The shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. In this challenge we will create a simple shellcode and test it.


## Goal

* Create a small program in assembly
* Transform that program into shellcode
* Update shellcode so it has the properties it requires
* Test the shellcode


## Source

* Source directory: `~/challenges/challenge04/`
* Source files: [challenge04](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge04)

There are four relevant files:
* print.asm
* print2.asm
* print3.asm
* shellcodetest.c

You can compile it by calling `make` in the folder `~/challenges/challenge04`
But steps to manually compile it are written below.


## Step 1: A simple asssembler program

We have a simple assembler program, which should print the message "Hi there" on the console:
```asm
$ cat print.asm
section .data
msg db 'Hi there',0xa

section .text
global _start
_start:

; write (int fd, char *msg, unsigned int len);
mov eax, 4
mov ebx, 1
mov ecx, msg
mov edx, 9
int 0x80

; exit (int ret)
mov eax, 1
mov ebx, 0
int 0x80
```

### Generate executable

Compile it:
```
$ nasm -f elf print.asm
```

This should generate an object ELF file with the name `print.o`.

Link it with the linker `ld`:
```
$ ld -m elf_i386 -o print print.o
```

This will generate an executable file "print". Note that we link it as x32, because the source assembler code is in x32. Alternatively just type `make print`.

Try it:
```
$ ./print
Hi there
$
```

It looks like our code is working.

### Disassembly

We can decompile the generated ELF binary, to check the assembler source code again. Note that the initial program was written in Intel syntax, but objdump will use AT&T syntax.

```
~/challenges/challenge04$ objdump -d print

print:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:       b8 04 00 00 00          mov    $0x4,%eax
 8049005:       bb 01 00 00 00          mov    $0x1,%ebx
 804900a:       b9 00 a0 04 08          mov    $0x804a000,%ecx
 804900f:       ba 09 00 00 00          mov    $0x9,%edx
 8049014:       cd 80                   int    $0x80
 8049016:       b8 01 00 00 00          mov    $0x1,%eax
 804901b:       bb 00 00 00 00          mov    $0x0,%ebx
 8049020:       cd 80                   int    $0x80
```

### Create shellcode

Extract byte-shellcode out of your executable using objdump output
```
$ objdump -d print | grep "^ " \
 | cut -d$'\t' -f 2 | tr '\n' ' ' | sed -e 's/ *$//' \
 | sed -e 's/ \+/\\x/g' | awk '{print "\\x"$0}'

\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xb9\x00\xa0\x04\x08\xba\x09\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80
```

The command line above will extract the byte sequence of the program. Sadly we have a lot of 0 bytes `\x00` in the shellcode. We also have a static reference.

We have to remove the 0 bytes, and the static reference, as 0 bytes are considered as string termination, and should not appear in bytecode.


## Step 2: Remove 0-bytes from bytecode

Now we will convert the existing print.asm source code to a shellcode which does
not contain 0-bytes. For this we strip out assembler instructions which inherently
use 0-bytes, and exchange them with equivalent functions without 0-bytes.

For example we'll exchange `mov eax, 4` with `xor eax, eax` followed by `mov al, 4`.

Original: 
```
 8049000:       b8 04 00 00 00          mov    $0x4,%eax
```

Replaced: 
```
 8049000:       31 c0                   xor    %eax,%eax
 8049008:       b0 04                   mov    $0x4,%al
```

`print2.asm` with all the improvements:
```
section .data
msg db 'Hi there',0xa

section .text
global _start
_start:

xor eax,eax
xor ebx,ebx
xor ecx,ecx
xor edx,edx

mov al, 0x4
mov bl, 0x1
mov ecx, msg
mov dl, 0x8
int 0x80

mov al, 0x1
xor ebx,ebx
int 0x80
```

Compile and link it:
```
$ nasm -f elf print2.asm
$ ld -m elf_i386 -o print2 print2.o
```

or build it via `make print2`.

Run it:
```
$ ./print2
Hi there
```

Seems it's still working. But are the 0 bytes removed? Lets check:
```
~/challenges/challenge04$ objdump -d print2

print2:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:       31 c0                   xor    %eax,%eax
 8049002:       31 db                   xor    %ebx,%ebx
 8049004:       31 c9                   xor    %ecx,%ecx
 8049006:       31 d2                   xor    %edx,%edx
 8049008:       b0 04                   mov    $0x4,%al
 804900a:       b3 01                   mov    $0x1,%bl
 804900c:       b9 00 a0 04 08          mov    $0x804a000,%ecx
 8049011:       b2 08                   mov    $0x8,%dl
 8049013:       cd 80                   int    $0x80
 8049015:       b0 01                   mov    $0x1,%al
 8049017:       31 db                   xor    %ebx,%ebx
 8049019:       cd 80                   int    $0x80
```

Awesome, no more 0x00 bytes! But we still have a problem with the hard-coded address $0x804909c (this causes problems in a real shellcode).


## Step 3: Remove References

We need to remove the reference to the data section. For this, we just push the bytes of the message 'hi there' on the stack, and reference that string relative to the stack pointer.


### Convert string to number

We will `push` the bytes of the string onto the stack. For this we wil first get
the hexadecimal representation of the string. Then we will convert it to two 32-bit
(4-bytes) little endian numbers.


Create BYTES of message "Hi there"
```
~/challenges/challenge04$ echo "Hi there" | hexdump -C
00000000  48 69 20 74 68 65 72 65  0a                       |Hi there.|
          ----------- -----------
```

Lets convert it to little endian, by splitting it into two 32bit / 4 byte values. 
We can ignore the last byte 0x0a which is the newline. 
```
to little endian: 68 65 72 65 --> 65 72 65 68
to little endian: 48 69 20 74 --> 74 20 69 48
```

There we have the two 32 bit numbers 0x65726568 and 0x74206948 as result. 


### Write new ASM sourcecode

Create new ASM file with built-in message 'hi there'. 

After executing:
```
push 0x65726568
push 0x74206948
```

The stack will look like: 
```
68 65 72 65
48 69 20 74 
```

Or more naturally: 
```
48 69 20 74 68 65 72 65
```

With ESP pointing to the address of the first 0x48 byte. 
We can just copy ESP to the ECX register as argument for the syscall:
```
mov ecx, esp
```

Result:
```
$ cat print3.asm
section .data

section .text
global _start
_start:

xor eax,eax
xor ebx,ebx
xor ecx,ecx
xor edx,edx

mov al, 0x4
mov bl, 0x1
mov dl, 0x8
push 0x65726568
push 0x74206948
mov ecx, esp
int 0x80

mov al, 0x1
xor ebx,ebx
int 0x80
```


### Create new executable

Compile and link it:

```
$ nasm -f elf print3.asm
$ ld -o print3 -m elf_i386 print3.o
```

or `make print3`

Try it:
```
$ ./print3
Hi there
```

### how does it work?

Note that the parameter for the write() system call before the 0x80 interrupt
is just a copy of ESP. Because we pushed the two 32-bit integer onto the stack
(which represent our text), ESP is pointing to our generated string.

```sh
~/challenges/challenge04$ objdump -d print2

print2:     file format elf32-i386


Disassembly of section .text:

08049000 <_start>:
 8049000:       31 c0                   xor    %eax,%eax
 8049002:       31 db                   xor    %ebx,%ebx
 8049004:       31 c9                   xor    %ecx,%ecx
 8049006:       31 d2                   xor    %edx,%edx
 8049008:       b0 04                   mov    $0x4,%al
 804900a:       b3 01                   mov    $0x1,%bl
 804900c:       b9 00 a0 04 08          mov    $0x804a000,%ecx
 8049011:       b2 08                   mov    $0x8,%dl
 8049013:       cd 80                   int    $0x80
 8049015:       b0 01                   mov    $0x1,%al
 8049017:       31 db                   xor    %ebx,%ebx
 8049019:       cd 80                   int    $0x80
~/challenges/challenge04$ gdb -q print3
Reading symbols from print3...
(No debugging symbols found in print3)
(gdb) disas _start
Dump of assembler code for function _start:
   0x08049000 <+0>:     xor    eax,eax
   0x08049002 <+2>:     xor    ebx,ebx
   0x08049004 <+4>:     xor    ecx,ecx
   0x08049006 <+6>:     xor    edx,edx
   0x08049008 <+8>:     mov    al,0x4
   0x0804900a <+10>:    mov    bl,0x1
   0x0804900c <+12>:    mov    dl,0x8
   0x0804900e <+14>:    push   0x65726568
   0x08049013 <+19>:    push   0x74206948
   0x08049018 <+24>:    mov    ecx,esp
   0x0804901a <+26>:    int    0x80
   0x0804901c <+28>:    mov    al,0x1
   0x0804901e <+30>:    xor    ebx,ebx
   0x08049020 <+32>:    int    0x80
End of assembler dump.
(gdb) b *_start+26
Breakpoint 1 at 0x804901a
(gdb) r
Starting program: /root/challenges/challenge04/print3

Breakpoint 1, 0x0804901a in _start ()
(gdb) i r esp
esp            0xffffdd98          0xffffdd98
(gdb) x/1s $esp
0xffffdd98:     "Hi there\001"
```


## Create shellcode

Dump your shellcode from print3:
```
$ objdump -d print3 | grep "^ " | cut -d$'\t' -f 2 | tr '\n' ' ' | sed -e 's/ *$//' | sed -e 's/ \+/\\x/g'| awk '{print "\\x"$0}'
\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb3\x01\xb2\x08\x68\x68\x65\x72\x65\x68\x48\x69\x20\x74\x89\xe1\xcd\x80\xb0\x01\x31\xdb\xcd\x80
```

We can now use this bytecode sequence, and use it in our shellcode test program.


### Test Shellcode with Loader

You can now try the new shellcode in a shellcode loader program. 
We copy the shellcode into a stack variable, and execute it:

```c
#include <stdio.h>
#include <string.h>

char *shellcode = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb3\x01\xb2\x08\x68\x68\x65\x72\x65\x68\x48\x69\x20\x74\x89\xe1\xcd\x80\xb0\x01\x31\xdb\xcd\x80";

int main(void) {
        char stackShellcode[128];
        memcpy(stackShellcode, shellcode, strlen(shellcode));
        ( *( void(*)() ) stackShellcode)();
}
```

Lets execute it:
```
$ gcc shellcodetest.c –m32 –z execstack -o shellcodetest
$ ./shellcodetest
Hi there
$
```

Seems to work. Lets debug it in GDB too. We will set a breakpoint at the `call eax` instruction:

```
~/challenges/challenge04$ gdb -q shellcodetest
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 10.1.90.20210103-git in 0.00ms using Python engine 3.9
Reading symbols from shellcodetest...
(No debugging symbols found in shellcodetest)
gef➤  disas main
Dump of assembler code for function main:
   0x08049172 <+0>:     lea    ecx,[esp+0x4]
   0x08049176 <+4>:     and    esp,0xfffffff0
   0x08049179 <+7>:     push   DWORD PTR [ecx-0x4]
   0x0804917c <+10>:    push   ebp
   0x0804917d <+11>:    mov    ebp,esp
   0x0804917f <+13>:    push   ebx
   0x08049180 <+14>:    push   ecx
   0x08049181 <+15>:    add    esp,0xffffff80
   0x08049184 <+18>:    call   0x80490b0 <__x86.get_pc_thunk.bx>
   0x08049189 <+23>:    add    ebx,0x2e77
   0x0804918f <+29>:    mov    eax,DWORD PTR [ebx+0x20]
   0x08049195 <+35>:    sub    esp,0xc
   0x08049198 <+38>:    push   eax
   0x08049199 <+39>:    call   0x8049040 <strlen@plt>
   0x0804919e <+44>:    add    esp,0x10
   0x080491a1 <+47>:    mov    edx,DWORD PTR [ebx+0x20]
   0x080491a7 <+53>:    sub    esp,0x4
   0x080491aa <+56>:    push   eax
   0x080491ab <+57>:    push   edx
   0x080491ac <+58>:    lea    eax,[ebp-0x88]
   0x080491b2 <+64>:    push   eax
   0x080491b3 <+65>:    call   0x8049030 <memcpy@plt>
   0x080491b8 <+70>:    add    esp,0x10
   0x080491bb <+73>:    lea    eax,[ebp-0x88]
   0x080491c1 <+79>:    call   eax
   0x080491c3 <+81>:    mov    eax,0x0
   0x080491c8 <+86>:    lea    esp,[ebp-0x8]
   0x080491cb <+89>:    pop    ecx
   0x080491cc <+90>:    pop    ebx
   0x080491cd <+91>:    pop    ebp
   0x080491ce <+92>:    lea    esp,[ecx-0x4]
   0x080491d1 <+95>:    ret
End of assembler dump.

gef➤  b *main+79
Breakpoint 1 at 0x80491c1
gef➤  r
Starting program: /root/challenges/challenge04/shellcodetest

Breakpoint 1, 0x080491c1 in main ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffdc50  →  0xdb31c031
$ebx   : 0x804c000  →  0x804bf14  →  <_DYNAMIC+0> add DWORD PTR [eax], eax
$ecx   : 0x0
$edx   : 0xf7fc1000  →  0x001e4d6c
$esp   : 0xffffdc50  →  0xdb31c031
$ebp   : 0xffffdcd8  →  0x00000000
$esi   : 0xf7fc1000  →  0x001e4d6c
$edi   : 0xf7fc1000  →  0x001e4d6c
$eip   : 0x80491c1  →  <main+79> call eax
──────────────────────────────────────────────────────────────── code:x86:32 ────
    0x80491b3 <main+65>        call   0x8049030 <memcpy@plt>
    0x80491b8 <main+70>        add    esp, 0x10
    0x80491bb <main+73>        lea    eax, [ebp-0x88]
 →  0x80491c1 <main+79>        call   eax
    0x80491c3 <main+81>        mov    eax, 0x0
──────────────────────────────────────────────────────── arguments (guessed) ────
*0xffffffffffffdc50 (
   [sp + 0x0] = 0xdb31c031,
   [sp + 0x4] = 0xd231c931
)
───────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "shellcodetest", stopped 0x80491c1 in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────

gef➤  x/8i $eax
   0xffffdc50:  xor    eax,eax
   0xffffdc52:  xor    ebx,ebx
   0xffffdc54:  xor    ecx,ecx
   0xffffdc56:  xor    edx,edx
   0xffffdc58:  mov    al,0x4
   0xffffdc5a:  mov    bl,0x1
   0xffffdc5c:  mov    dl,0x8
   0xffffdc5e:  push   0x65726568
gef➤
```

`call eax` will jump to our shellcode on the stack. Issue `ni` command to 
execute the next instruction:

```
gef➤  ni
0xffffdc50 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xffffdc50  →  0xdb31c031
$ebx   : 0x804c000  →  0x804bf14  →  <_DYNAMIC+0> add DWORD PTR [eax], eax
$ecx   : 0x0
$edx   : 0xf7fc1000  →  0x001e4d6c
$esp   : 0xffffdc4c  →  0x80491c3  →  <main+81> mov eax, 0x0
$ebp   : 0xffffdcd8  →  0x00000000
$esi   : 0xf7fc1000  →  0x001e4d6c
$edi   : 0xf7fc1000  →  0x001e4d6c
$eip   : 0xffffdc50  →  0xdb31c031
────────────────────────────────────────────────────────────────────────── code:x86:32 ────
   0xffffdc4c                  ret
   0xffffdc4d                  xchg   ecx, eax
   0xffffdc4e                  add    al, 0x8
 → 0xffffdc50                  xor    eax, eax
   0xffffdc52                  xor    ebx, ebx
────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "shellcodetest", stopped 0xffffdc50 in ?? (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────
```

We can see that we happily execute `xor eax, eax` at address `0xffffdc50` next. Our shellcode. 


# Things to think about

* Can you make the shellcode smaller? How small?
* Instead of using the system call write(), use the system call 11 (0xb), "sys_execve". Start a bash shell instead of printing 'hi there'
* Can you do this challenge in 64 bit?
