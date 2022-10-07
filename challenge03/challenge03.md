# Introduction to hex numbers, code and GDB

## Introduction

We will compile some assembler code to see the relationship between
hex and decimal numbers, registers and memory.

As there is no interactive assembler, we will compile the assembler code into a
executable. By loading it into a debugger (GDB), we can single-step every
instruction and its behaviour.

A nice side effect is that we see GDB in action, which we will use
a lot later on.


## Goal

* Learn about assembly
* Learn how to debug an assembly program
* Learn how to interpret the output of GDB, gef


## Source

* Source directory: `~/challenges/challenge03/`
* Source files: [challenge03](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge03)

You can compile it by calling `make` in the folder `~/challenges/challenge03`

Source:
```c
section .data
msg db 'AABBCCDD'


section .text
global _start
_start:

mov eax, 10
mov ah, 0x1
add eax, 0x10

mov eax, 0x11223344

mov ebx, 0x8048001
mov eax, [ebx]

mov ebx, 0x41424344
mov eax, [ebx]
```


### Generate executable

Compile it:
```
$ nasm -f elf intro.asm
```

This should generate an object ELF file with the name `intro.o`.

Link it with the linker `ld`:
```
$ ld -m elf_i386 -o intro intro.o
```

This will generate an executable file "intro". Note that we link it as x32, because the source assembler code is in x32. Alternatively just type `make intro`.


## Load the program

Lets use `gdb` to load the program. We will stop the execution before
the first relevant assembler instruction.


Start `gdb` with `intro` executable. The `-q` parameter just omits some
irrelevant messages on startup.
```
~/challenges/challenge03$ gdb -q intro
GEF for linux ready, type `gef' to start, `gef config' to configure
90 commands loaded and 5 functions added for GDB 10.1.90.20210103-git in 0.00ms using Python engine 3.9
Reading symbols from intro...
(No debugging symbols found in intro)
gef➤ 
```

Lets set a breakpoint at the label `_start`:
```
gef➤  b *_start
Breakpoint 1 at 0x8049000
```

Lets start the program. Execution will be stopped when it reaches the breakpoint
we have set.
```
gef➤  run
Starting program: /root/challenges/challenge03/intro

Breakpoint 1, 0x08049000 in _start ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x0
$ebx   : 0x0
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffffdda0  →  0x00000001
$ebp   : 0x0
$esi   : 0x0
$edi   : 0x0
$eip   : 0x8049000  →  <_start+0> mov eax, 0xa
─────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048ffa                  add    BYTE PTR [eax], al
    0x8048ffc                  add    BYTE PTR [eax], al
    0x8048ffe                  add    BYTE PTR [eax], al
 →  0x8049000 <_start+0>       mov    eax, 0xa
    0x8049005 <_start+5>       mov    ah, 0x1
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "intro", stopped 0x8049000 in _start (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────
```

We can see: 
* The content of the registers
* The assembly code, and where we are currently stopped
* GDB output on its state


Lets orient ourselves with some gdb commands:
```
gef➤  where
#0  0x08049000 in _start ()
gef➤  disas
Dump of assembler code for function _start:
=> 0x08049000 <+0>:     mov    eax,0xa
   0x08049005 <+5>:     mov    ah,0x1
   0x08049007 <+7>:     add    eax,0x10
   0x0804900a <+10>:    mov    eax,0x11223344
   0x0804900f <+15>:    mov    ebx,0x8048001
   0x08049014 <+20>:    mov    eax,DWORD PTR [ebx]
   0x08049016 <+22>:    mov    ebx,0x41424344
   0x0804901b <+27>:    mov    eax,DWORD PTR [ebx]
End of assembler dump.
```

With the command `disas`, we can not only see the compiled assembler code,
but also where we are currently in its execution, the line is indicated
by `=>`. Note that it will point at the *next* instruction to be executed,
not the one which is already executed (exactly like EIP/RIP/PC).

We will now execute each instruction after the other with the GDB command
`ni` (next instruction), and observe its impact.


## Executing: Command 1

Lets execute the first instruction: `mov $0xa,%eax`.

```
gef➤  ni
0x08049005 in _start ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xa
$ebx   : 0x0
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffffdda0  →  0x00000001
$ebp   : 0x0
$esi   : 0x0
$edi   : 0x0
$eip   : 0x8049005  →  <_start+5> mov ah, 0x1
─────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048ffc                  add    BYTE PTR [eax], al
    0x8048ffe                  add    BYTE PTR [eax], al
    0x8049000 <_start+0>       mov    eax, 0xa
 →  0x8049005 <_start+5>       mov    ah, 0x1
    0x8049007 <_start+7>       add    eax, 0x10
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "intro", stopped 0x8049005 in _start (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r eax
eax            0xa                 0xa
```

We have written the number 0xa, or 10 in decimal, into register `eax`.


## Executing: Command 2

Lets execute: `mov    $0x1,%ah`
```
gef➤  ni
0x08049007 in _start ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x10a
$ebx   : 0x0
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffffdda0  →  0x00000001
$ebp   : 0x0
$esi   : 0x0
$edi   : 0x0
$eip   : 0x8049007  →  <_start+7> add eax, 0x10
─────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048ffe                  add    BYTE PTR [eax], al
    0x8049000 <_start+0>       mov    eax, 0xa
    0x8049005 <_start+5>       mov    ah, 0x1
 →  0x8049007 <_start+7>       add    eax, 0x10
    0x804900a <_start+10>      mov    eax, 0x11223344
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "intro", stopped 0x8049007 in _start (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r eax
eax            0x10a               0x10a
```

We have written the number 0x1 into `ah`. This is the "higher" part of `ax`.
`ax` is the lower 16 bits of `eax`. This doesnt overwrite the 0x1 we have
written in `eax`, because it is covered by `al`.

Remember, `eax` is 32 bit or 4 byte. `ah` is the 3rd byte, while `al` is the 4th.
`ax` is 16 bit or 2 bytes, or the 2nd half of `eax`.

One byte is represented by two hex digits. Therefore both `al` and `ah` require
2 hex digits to describe them each. `eax`, 4 bytes, requires 8 hex digits.


## Executing: Command 3

Lets execute: `add    $0x10,%eax`

```
gef➤  ni
0x0804900a in _start ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x11a
$ebx   : 0x0
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffffdda0  →  0x00000001
$ebp   : 0x0
$esi   : 0x0
$edi   : 0x0
$eip   : 0x804900a  →  <_start+10> mov eax, 0x11223344
─────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8048fff                  add    BYTE PTR [eax+0xa], bh
    0x8049005 <_start+5>       mov    ah, 0x1
    0x8049007 <_start+7>       add    eax, 0x10
 →  0x804900a <_start+10>      mov    eax, 0x11223344
    0x804900f <_start+15>      mov    ebx, 0x8048001
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "intro", stopped 0x804900a in _start (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r eax
eax            0x11a               0x11a
```

Because:
```
0x10a + 0x10 = 0x11a
```


## Executing: Command 4

Lets execute: `mov    $0x11223344,%eax`
```
gef➤  ni
0x0804900f in _start ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x11223344
$ebx   : 0x0
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffffdda0  →  0x00000001
$ebp   : 0x0
$esi   : 0x0
$edi   : 0x0
$eip   : 0x804900f  →  <_start+15> mov ebx, 0x8048001
─────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049005 <_start+5>       mov    ah, 0x1
    0x8049007 <_start+7>       add    eax, 0x10
    0x804900a <_start+10>      mov    eax, 0x11223344
 →  0x804900f <_start+15>      mov    ebx, 0x8048001
    0x8049014 <_start+20>      mov    eax, DWORD PTR [ebx]
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "intro", stopped 0x804900f in _start (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r eax ah al
eax            0x11223344          0x11223344
ah             0x33                0x33
al             0x44                0x44
```

The output of `eax`, `ah` and `al` should be clear.


## Executing: Command 5

Here we execute two assembly instruction to reach our goal:
```
   0x0804808f <+15>:    mov    $0x8048001,%ebx
   0x08048094 <+20>:    mov    (%ebx),%eax
```

The first will load the address `0x8048001` into `ebx`.
The second will load the content of that memory address (`0x8048001`) into eax.

```
gef➤  ni
0x08049014 in _start ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x11223344
$ebx   : 0x8048001  →   inc ebp
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffffdda0  →  0x00000001
$ebp   : 0x0
$esi   : 0x0
$edi   : 0x0
$eip   : 0x8049014  →  <_start+20> mov eax, DWORD PTR [ebx]
─────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049007 <_start+7>       add    eax, 0x10
    0x804900a <_start+10>      mov    eax, 0x11223344
    0x804900f <_start+15>      mov    ebx, 0x8048001
 →  0x8049014 <_start+20>      mov    eax, DWORD PTR [ebx]
    0x8049016 <_start+22>      mov    ebx, 0x41424344
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "intro", stopped 0x8049014 in _start (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r eax ebx
eax            0x11223344          0x11223344
ebx            0x8048001           0x8048001
```

`eax` still has the old content, while `ebx` contains the memory address.
Lets load the data at it:

```
gef➤  ni
0x08049016 in _start ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1464c45
$ebx   : 0x8048001  →   inc ebp
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffffdda0  →  0x00000001
$ebp   : 0x0
$esi   : 0x0
$edi   : 0x0
$eip   : 0x8049016  →  <_start+22> mov ebx, 0x41424344
─────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804900a <_start+10>      mov    eax, 0x11223344
    0x804900f <_start+15>      mov    ebx, 0x8048001
    0x8049014 <_start+20>      mov    eax, DWORD PTR [ebx]
 →  0x8049016 <_start+22>      mov    ebx, 0x41424344
    0x804901b <_start+27>      mov    eax, DWORD PTR [ebx]
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "intro", stopped 0x8049016 in _start (), reason: SINGLE STEP
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r eax ebx
eax            0x1464c45           0x1464c45
ebx            0x8048001           0x8048001
```

It seems the 4 byte (32 bit) value at memory location `0x8048001` is
`0x1464c45`.

Memory locations are different from registers, as they are 1-byte (8 bit)
referenced. Lets use GDB to have a look at that memory location in `ebx` again.


Lets display it as one Word (32 bit):
```
gef➤  x/1wx $ebx
0x8048001:      0x01464c45
```
Same result as in the register `eax`.

Now, lets have a look at 4 bytes:
```
gef➤  x/4bx $ebx
0x8048001:      0x45    0x4c    0x46    0x01
```
The order is reversed!

Note that register `eax` is stored as little endian, as we have seen when we
accessed `al` and `ah`, and also `ax`.

In memory, we can try to display a memory location as a little endian 32 bit
integer, as we did with the GDB command `x/1wx`. It will automagically convert
the number at that memory location, as it knows it is a little endian machine.

If we look at the individual bytes though, we see that the number `0x01464c45`
is actually stored as 4 bytes: `0x45 0x4c 0x46 0x01`. Or in other words, the byte
at memory location `0x8048001` is `0x45`. The byte at memory location
`0x8048001 + 1 = 0x8048002` is `0x4c`.

The bytes appear to be a string. Lets have a look at it:
```
gef➤  x/1s $ebx
0x8048001:      "ELF\001\001\001"
```

It seems to be the string "ELF", followed by three 0x01 bytes.

So we can look at the same memory location, like `0x8048001`, in three ways:
* First: as a 32-bit little endian integer
* Second: as 4 independant, individual bytes
* Third: Interpret these bytes as ASCII, and display it like a string


## Executing: Command 6

This time, we will do the same as in the previous chapter, but we will access an "invalid"
memory location, in this case `0x41424344`, and see what happens:
```
gef➤  i r eax ebx
eax            0x1464c45           0x1464c45
ebx            0x41424344          0x41424344
gef➤  ni

Program received signal SIGSEGV, Segmentation fault.
0x0804901b in _start ()
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0x1464c45
$ebx   : 0x41424344 ("DCBA"?)
$ecx   : 0x0
$edx   : 0x0
$esp   : 0xffffdda0  →  0x00000001
$ebp   : 0x0
$esi   : 0x0
$edi   : 0x0
$eip   : 0x804901b  →  <_start+27> mov eax, DWORD PTR [ebx]
─────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x804900f <_start+15>      mov    ebx, 0x8048001
    0x8049014 <_start+20>      mov    eax, DWORD PTR [ebx]
    0x8049016 <_start+22>      mov    ebx, 0x41424344
 →  0x804901b <_start+27>      mov    eax, DWORD PTR [ebx]
    0x804901d                  add    BYTE PTR [eax], al
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "intro", stopped 0x804901b in _start (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r eax ebx
eax            0x1464c45           0x1464c45
ebx            0x41424344          0x41424344
```

The program crashed with the error code "SIGSEGV", Segmentation fault.

This is one of the reasons why the instruction pointer points to the next command:
We know exactly at which point the program failed.

The memory address `0x41424344` is not mapped in the process, therefore every access to it
will generate a "segmentation fault". 
