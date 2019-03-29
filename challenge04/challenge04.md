# Introduction to hex numbers, code and GDB

## Introduction

We will compile some assembler code to see the relationship between
hex and decimal numbers, registers and memory.

As there is no interactive assembler, we will compile the assembler code into a
executable. By loading it into a debugger (GDB), we can single-step every
instruction and its behaviour.

A nice side effect is that we see GDB in action, which we will use
a lot later on.


## Files

Source directory: `~/challenges/challenge04/`

There is one relevant file:
* intro.asm


## Source

File  `~/challenges/challenge04/intro.asm`:
```
$ cat intro.asm
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
root@hlUbuntu32:~/challenges/challenge04# gdb -q ./intro
Reading symbols from ./intro...(no debugging symbols found)...done.
```

Lets set a breakpoint at the label `_start`:
```
(gdb) b *_start
Breakpoint 1 at 0x8048080
```

Lets start the program. Execution will be stopped when it reaches the breakpoint
we have set.
```
(gdb) run
Starting program: /root/challenges/challenge04/intro

Breakpoint 1, 0x08048080 in _start ()
(gdb) where
#0  0x08048080 in _start ()
(gdb) disas
Dump of assembler code for function _start:
=> 0x08048080 <+0>:     mov    $0xa,%eax
   0x08048085 <+5>:     mov    $0x1,%ah
   0x08048087 <+7>:     add    $0x10,%eax
   0x0804808a <+10>:    mov    $0x11223344,%eax
   0x0804808f <+15>:    mov    $0x8048001,%ebx
   0x08048094 <+20>:    mov    (%ebx),%eax
   0x08048096 <+22>:    mov    $0x41424344,%ebx
   0x0804809b <+27>:    mov    (%ebx),%eax
   0x0804809d <+29>:    mov    $0x1,%eax
   0x080480a2 <+34>:    mov    $0x0,%ebx
   0x080480a7 <+39>:    int    $0x80
End of assembler dump.
```

With the command `disas`, we can not only see the compiled assembler code,
but also where we are currently in its execution, the line is indicated
by `=>`. Note that it will point at the *next* instruction to be executed,
not the one which is already executed (exactly like EIP/RIP/PC).

We will now execute each instruction after the other with the GDB command
`ni` (next instruction), and observe its impact.

## Command 1

Lets execute the first instruction: `mov $0xa,%eax`.

```
(gdb) ni
(gdb) disas
Dump of assembler code for function _start:
   0x08048080 <+0>:     mov    $0xa,%eax
=> 0x08048085 <+5>:     mov    $0x1,%ah
   0x08048087 <+7>:     add    $0x10,%eax
   0x0804808a <+10>:    mov    $0x11223344,%eax
   0x0804808f <+15>:    mov    $0x8048001,%ebx
   0x08048094 <+20>:    mov    (%ebx),%eax
   0x08048096 <+22>:    mov    $0x41424344,%ebx
   0x0804809b <+27>:    mov    (%ebx),%eax
   0x0804809d <+29>:    mov    $0x1,%eax
   0x080480a2 <+34>:    mov    $0x0,%ebx
   0x080480a7 <+39>:    int    $0x80
End of assembler dump.
(gdb) i r eax
eax            0xa      10
```

We have written the number 0xa, or 10 in decimal, into register `eax`.

## Command 2

Lets execute: `mov    $0x1,%ah`
```
(gdb) ni
0x08048087 in _start ()
(gdb) disas
Dump of assembler code for function _start:
   0x08048080 <+0>:     mov    $0xa,%eax
   0x08048085 <+5>:     mov    $0x1,%ah
=> 0x08048087 <+7>:     add    $0x10,%eax
   0x0804808a <+10>:    mov    $0x11223344,%eax
   0x0804808f <+15>:    mov    $0x8048001,%ebx
   0x08048094 <+20>:    mov    (%ebx),%eax
   0x08048096 <+22>:    mov    $0x41424344,%ebx
   0x0804809b <+27>:    mov    (%ebx),%eax
   0x0804809d <+29>:    mov    $0x1,%eax
   0x080480a2 <+34>:    mov    $0x0,%ebx
   0x080480a7 <+39>:    int    $0x80
End of assembler dump.
(gdb) i r eax
eax            0x10a    266
```

We have written the number 0x1 into `ah`. This is the "higher" part of `ax`.
`ax` is the lower 16 bits of `eax`. This doesnt overwrite the 0x1 we have
written in `eax`, because it is covered by `al`.

Remember, `eax` is 32 bit or 4 byte. `ah` is the 3rd byte, while `al` is the 4th.
`ax` is 16 bit or 2 bytes, or the 2nd half of `eax`.

One byte is represented by two hex digits. Therefore both `al` and `ah` require
2 hex digits to describe them each. `eax`, 4 bytes, requires 8 hex digits.

## Command 3

Lets execute: `add    $0x10,%eax`

```
(gdb) ni
0x0804808a in _start ()
(gdb) disas
Dump of assembler code for function _start:
   0x08048080 <+0>:     mov    $0xa,%eax
   0x08048085 <+5>:     mov    $0x1,%ah
   0x08048087 <+7>:     add    $0x10,%eax
=> 0x0804808a <+10>:    mov    $0x11223344,%eax
   0x0804808f <+15>:    mov    $0x8048001,%ebx
   0x08048094 <+20>:    mov    (%ebx),%eax
   0x08048096 <+22>:    mov    $0x41424344,%ebx
   0x0804809b <+27>:    mov    (%ebx),%eax
   0x0804809d <+29>:    mov    $0x1,%eax
   0x080480a2 <+34>:    mov    $0x0,%ebx
   0x080480a7 <+39>:    int    $0x80
End of assembler dump.
(gdb) i r eax
eax            0x11a    282
```

Calc:
```
0x10a + 0x10 = 0x11a
```

## Command 4

Lets execute: `mov    $0x11223344,%eax`
```
(gdb) ni
0x0804808f in _start ()
(gdb) disas
Dump of assembler code for function _start:
   0x08048080 <+0>:     mov    $0xa,%eax
   0x08048085 <+5>:     mov    $0x1,%ah
   0x08048087 <+7>:     add    $0x10,%eax
   0x0804808a <+10>:    mov    $0x11223344,%eax
=> 0x0804808f <+15>:    mov    $0x8048001,%ebx
   0x08048094 <+20>:    mov    (%ebx),%eax
   0x08048096 <+22>:    mov    $0x41424344,%ebx
   0x0804809b <+27>:    mov    (%ebx),%eax
   0x0804809d <+29>:    mov    $0x1,%eax
   0x080480a2 <+34>:    mov    $0x0,%ebx
   0x080480a7 <+39>:    int    $0x80
End of assembler dump.
(gdb) i r eax ah al
eax            0x11223344       287454020
ah             0x33     51
al             0x44     68
```

The output of `eax`, `ah` and `al` should be clear.


## Command 5

Here we execute two assembly instruction to reach our goal:
```
   0x0804808f <+15>:    mov    $0x8048001,%ebx
   0x08048094 <+20>:    mov    (%ebx),%eax
```

The first will load the address `0x8048001` into `ebx`.
The second will load the content of that memory address (`0x8048001`) into eax.

```
(gdb) disas
Dump of assembler code for function _start:
   0x08048080 <+0>:     mov    $0xa,%eax
   0x08048085 <+5>:     mov    $0x1,%ah
   0x08048087 <+7>:     add    $0x10,%eax
   0x0804808a <+10>:    mov    $0x11223344,%eax
=> 0x0804808f <+15>:    mov    $0x8048001,%ebx
   0x08048094 <+20>:    mov    (%ebx),%eax
   0x08048096 <+22>:    mov    $0x41424344,%ebx
   0x0804809b <+27>:    mov    (%ebx),%eax
   0x0804809d <+29>:    mov    $0x1,%eax
   0x080480a2 <+34>:    mov    $0x0,%ebx
   0x080480a7 <+39>:    int    $0x80
End of assembler dump.
(gdb) ni
0x08048094 in _start ()
(gdb) i r eax ebx
eax            0x11223344       287454020
ebx            0x8048001        134512641
```

`eax` still has the old content, while `ebx` contains the memory address.
Lets load the data at it:

```
(gdb) ni
0x08048096 in _start ()
(gdb) disas
Dump of assembler code for function _start:
   0x08048080 <+0>:     mov    $0xa,%eax
   0x08048085 <+5>:     mov    $0x1,%ah
   0x08048087 <+7>:     add    $0x10,%eax
   0x0804808a <+10>:    mov    $0x11223344,%eax
   0x0804808f <+15>:    mov    $0x8048001,%ebx
   0x08048094 <+20>:    mov    (%ebx),%eax
=> 0x08048096 <+22>:    mov    $0x41424344,%ebx
   0x0804809b <+27>:    mov    (%ebx),%eax
   0x0804809d <+29>:    mov    $0x1,%eax
   0x080480a2 <+34>:    mov    $0x0,%ebx
   0x080480a7 <+39>:    int    $0x80
End of assembler dump.
(gdb) i r eax ebx
eax            0x1464c45        21384261
ebx            0x8048001        134512641
```

It seems the 4 byte (32 bit) value at memory location `0x8048001` is
`0x1464c45`.

Memory locations are different from registers, as they are 1-byte (8 bit)
referenced. Lets use GDB to have a look at that memory location in `ebx` again.


Lets display it as one Word (32 bit):
```
(gdb) x/1wx $ebx
0x8048001:      0x01464c45
```
Same result as in the register `eax`.

Now, lets have a look at 4 bytes:
```
(gdb) x/4bx $ebx
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
(gdb) x/1s $ebx
0x8048001:      "ELF\001\001\001"
```

It seems to be the string "ELF", followed by three 0x01 bytes.

So we can look at the same memory location, like `0x8048001`, in three ways:
* First: as a 32-bit little endian integer
* Second: as 4 independant, individual bytes
* Third: Interpret these bytes as ASCII, and display it like a string


## Command 6

This time, we will do the same as in the previous chapter, but we will access an "invalid"
memory location, in this case `0x41424344`, and see what happens:
```
(gdb) disas
Dump of assembler code for function _start:
   0x08048080 <+0>:     mov    $0xa,%eax
   0x08048085 <+5>:     mov    $0x1,%ah
   0x08048087 <+7>:     add    $0x10,%eax
   0x0804808a <+10>:    mov    $0x11223344,%eax
   0x0804808f <+15>:    mov    $0x8048001,%ebx
   0x08048094 <+20>:    mov    (%ebx),%eax
   0x08048096 <+22>:    mov    $0x41424344,%ebx
=> 0x0804809b <+27>:    mov    (%ebx),%eax
   0x0804809d <+29>:    mov    $0x1,%eax
   0x080480a2 <+34>:    mov    $0x0,%ebx
   0x080480a7 <+39>:    int    $0x80
End of assembler dump.
(gdb) i r eax, ebx
Invalid register `eax,'
(gdb) i r eax ebx
eax            0x1464c45        21384261
ebx            0x41424344       1094861636
(gdb) ni

Program received signal SIGSEGV, Segmentation fault.
0x0804809b in _start ()
```

The program crashed with the error code "SIGSEGV", Segmentation fault.

This is one of the reasons why the instruction pointer points to the next command:
We know exactly at which point the program failed.
