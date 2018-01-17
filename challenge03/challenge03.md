# Introduction to shellcode development

## Introduction

The shellcode is a small piece of code used as the payload in the exploitation of a software vulnerability. It is called "shellcode" because it typically starts a command shell from which the attacker can control the compromised machine, but any piece of code that performs a similar task can be called shellcode. In this challenge we will create a simple shellcode and test it.


## Goal

- Learn more about shellcode creation.
- How to create a shellcode from assembler
- How to test a shellcode


## Source

Source directory: `~/challenges/challenge03/`

There are four relevant files:
* print.asm
* print2.asm
* print3.asm
* shellcodetest.c

You can compile it by calling `make` in the folder `~/challenges/challenge03`.
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
# objdump -d print

print: file format elf32-i386


Disassembly of section .text:

08048080 <_start>:
8048080:   b8 04 00 00 00   mov  $0x4,%eax
8048085:   bb 01 00 00 00   mov  $0x1,%ebx
804808a:   b9 a4 90 04 08   mov  $0x80490a4,%ecx
804808f:   ba 09 00 00 00   mov  $0x9,%edx
8048094:   cd 80            int  $0x80
8048096:   b8 01 00 00 00   mov  $0x1,%eax
804809b:   bb 00 00 00 00   mov  $0x0,%ebx
80480a0:   cd 80            int  $0x80
```

### Create shellcode

Extract byte-shellcode out of your executable using objdump output
```
$ objdump -d print | grep "^ " \
 | cut -d$'\t' -f 2 | tr '\n' ' ' | sed -e 's/ *$//' \
 | sed -e 's/ \+/\\x/g' | awk '{print "\\x"$0}'

\xb8\x04\x00\x00\x00\xbb\x01\x00\x00\x00\xb9\xa4\x90\x04\x08\xba\x09\x00\x00\x00\xcd\x80\xb8\x01\x00\x00\x00\xbb\x00\x00\x00\x00\xcd\x80
```

The command line above will extract the byte sequence of the program. Sadly we have a lot of 0 bytes `\x00` in the shellcode. We also have a static reference.

We have to remove the 0 bytes, and the static reference, as 0 bytes are considered as string termination, and should not appear in bytecode.


## Step 2: Remove null-bytes from bytecode

Now we will convert the existing print.asm source code to a shellcode which does
not contain 0-bytes. For this we strip out assembler instructions which inherently
use 0-bytes, and exchange them with equivalent functions without 0-bytes.

For example we'll exchange `mov eax, 4` with `xor eax, eax` followed by `mov al, 4`.

`print2.asm`:
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
# objdump -d print2
print2: file format elf32-i386

Disassembly of section .text:
08048080 : <_start>
8048080: 31 c0           xor %eax,%eax
8048082: 31 db           xor %ebx,%ebx
8048084: 31 c9           xor %ecx,%ecx
8048086: 31 d2           xor %edx,%edx
8048088: b0 04           mov $0x4,%al
804808a: b3 01           mov $0x1,%bl
804808c: b9 9c 90 04 08  mov $0x804909c,%ecx
8048091: b2 08           mov $0x8,%dl
8048093: cd 80           int $0x80
8048095: b0 01           mov $0x1,%al
8048097: 31 db           xor %ebx,%ebx
8048099: cd 80           int $0x80
```

Awesome, no more null bytes! But we still have a problem with the hard-coded address $0x804909c (this causes problems in a real shellcode).


## Step 3: Remove References

We need to remove the reference to the data section. For this, we just push the bytes of the message 'hi there' on the stack, and reference that string relative to the stack pointer.


### Convert string to number

We will `push` the bytes of the string onto the stack. For this we wil first get
the hexadecimal representation of the string. Then we will convert it to two 32-bit
(4-bytes) little endian numbers.


Create BYTES of message "hi there"
```
$ python -c 'print "hi there"' | hexdump -C -v
00000000 68 69 20 74 68 65 72 65 0a |hi there.|
```

And convert it to little endian:
```
little endian: 68 65 72 65 --> 65 72 65 68
little endian: 68 69 20 74 --> 74 20 69 68
```

### Write new ASM sourcecode

Create new ASM file with built-in message 'hi there'
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
root@hlUbuntu32:~/challenges/challenge03# gdb print3
gdb-peda$ disas _start
Dump of assembler code for function _start:
   0x08048060 <+0>:     xor    eax,eax
   0x08048062 <+2>:     xor    ebx,ebx
   0x08048064 <+4>:     xor    ecx,ecx
   0x08048066 <+6>:     xor    edx,edx
   0x08048068 <+8>:     mov    al,0x4
   0x0804806a <+10>:    mov    bl,0x1
   0x0804806c <+12>:    mov    dl,0x8
   0x0804806e <+14>:    push   0x65726568
   0x08048073 <+19>:    push   0x74206948
   0x08048078 <+24>:    mov    ecx,esp
   0x0804807a <+26>:    int    0x80
   0x0804807c <+28>:    mov    al,0x1
   0x0804807e <+30>:    xor    ebx,ebx
   0x08048080 <+32>:    int    0x80
End of assembler dump.
gdb-peda$ b *0x0804807a
Breakpoint 1 at 0x804807a
gdb-peda$ r
Starting program: /root/challenges/challenge3/print3

 [----------------------------------registers-----------------------------------]
EAX: 0x4
EBX: 0x1
ECX: 0xffffd718 ("Hi there\001")
EDX: 0x8
ESI: 0x0
EDI: 0x0
EBP: 0x0
ESP: 0xffffd718 ("Hi there\001")
EIP: 0x804807a (<_start+26>:    int    0x80)
EFLAGS: 0x246 (carry PARITY adjust ZERO sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x804806e <_start+14>:       push   0x65726568
   0x8048073 <_start+19>:       push   0x74206948
   0x8048078 <_start+24>:       mov    ecx,esp
=> 0x804807a <_start+26>:       int    0x80
   0x804807c <_start+28>:       mov    al,0x1
   0x804807e <_start+30>:       xor    ebx,ebx
   0x8048080 <_start+32>:       int    0x80
   0x8048082:   add    BYTE PTR [eax],al
[------------------------------------stack-------------------------------------]
0000| 0xffffd718 ("Hi there\001")
0004| 0xffffd71c ("here\001")
0008| 0xffffd720 --> 0x1
0012| 0xffffd724 --> 0xffffd847 ("/root/challenges/challenge3/print3")
0016| 0xffffd728 --> 0x0
0020| 0xffffd72c --> 0xffffd86a ("TERM=xterm")
0024| 0xffffd730 --> 0xffffd875 ("SHELL=/bin/bash")
0028| 0xffffd734 --> 0xffffd885 ("SSH_CLIENT=212.254.178.176 57751 22")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804807a in _start ()

gdb-peda$ i r esp
esp            0xffffd718       0xffffd718
gdb-peda$ x/1s $esp
0xffffd718:     "Hi there\001"
```

## Create shellcode

Dump your shellcode from print3:
```
$ objdump -d print3 | grep "^ " | cut -d$'\t' -f 2 | tr '\n' ' ' | sed -e 's/ *$//' | sed -e 's/ \+/\\x/g'| awk '{print "\\x"$0}'
\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb3\x01\xb2\x08\x68\x68\x65\x72\x65\x68\x48\x69\x20\x74\x89\xe1\xcd\x80\xb0\x01\x31\xdb\xcd\x80
```

We can now use this bytecode sequence, and use it in our shellcode test program.

### Test Shellcode with Loader

You can now try the new shellcode in a shellcode loader program

Get print-shellcodetest.c
```
$ cat shellcodetest.c
#include <stdio.h>
#include <string.h>

char *shellcode = "\x31\xc0\x31\xdb\x31\xc9\x31\xd2\xb0\x04\xb3\x01\xb2\x08\x68\x68\x65\x72\x65\x68\x48\x69\x20\x74\x89\xe1\xcd\x80\xb0\x01\x31\xdb\xcd\x80";

int main(void) {
	( *( void(*)() ) shellcode)();
}
$ gcc shellcodetest.c –m32 –z execstack -o shellcodetest
$ ./shellcodetest
Hi there
$
```

## Missions

### Mission 1

Can you make the shellcode smaller? How small?

### Mission 1

Instead of using the system call write(), use the system call 11 (0xb), "sys_execve". Start a bash shell instead of printing 'hi there'

### Mission 2

Do the lab above for 64 bit.
