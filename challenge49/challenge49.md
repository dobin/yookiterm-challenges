# ARM64 Introduction

## General information

We use an AARCH64 ARM machine (virt-2.8 QEMU 2.8 ARM Virtual Machine).
This tutorial is based on the awesome Azeria Labs ARM tutorial: https://azeria-labs.com/writing-arm-shellcode/


# Exploit

## Call convention

Lets check a sample program:

Source:
```c
#include "stdio.h"

void handleData(char *arg) {
        char buf[8];
        strcpy(buf, arg);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("Call: %s <arg>\n", argv[0]);
        exit(0);
    }

    handleData(argv[1]);
}
```

And disassemble it:
```
$ gdb -q stack
Reading symbols from stack...(no debugging symbols found)...done.

(gdb) disas main
Dump of assembler code for function main:
   0x0000000000400674 <+0>:     stp     x29, x30, [sp,#-32]!
   0x0000000000400678 <+4>:     mov     x29, sp
   0x000000000040067c <+8>:     str     w0, [x29,#28]
   0x0000000000400680 <+12>:    str     x1, [x29,#16]
   0x0000000000400684 <+16>:    ldr     w0, [x29,#28]
   0x0000000000400688 <+20>:    cmp     w0, #0x2
   0x000000000040068c <+24>:    b.eq    0x4006ac <main+56>
   0x0000000000400690 <+28>:    ldr     x0, [x29,#16]
   0x0000000000400694 <+32>:    ldr     x1, [x0]
   0x0000000000400698 <+36>:    adrp    x0, 0x400000
   0x000000000040069c <+40>:    add     x0, x0, #0x760
   0x00000000004006a0 <+44>:    bl      0x4004f0 <printf@plt>
   0x00000000004006a4 <+48>:    mov     w0, #0x0                        // #0
   0x00000000004006a8 <+52>:    bl      0x4004a0 <exit@plt>
   0x00000000004006ac <+56>:    ldr     x0, [x29,#16]
   0x00000000004006b0 <+60>:    add     x0, x0, #0x8
   0x00000000004006b4 <+64>:    ldr     x0, [x0]
   0x00000000004006b8 <+68>:    bl      0x400650 <handleData>
   0x00000000004006bc <+72>:    mov     w0, #0x0                        // #0
   0x00000000004006c0 <+76>:    ldp     x29, x30, [sp],#32
   0x00000000004006c4 <+80>:    ret
End of assembler dump.
(gdb) disas handleData
Dump of assembler code for function handleData:
   0x0000000000400650 <+0>:     stp     x29, x30, [sp,#-48]!
   0x0000000000400654 <+4>:     mov     x29, sp
   0x0000000000400658 <+8>:     str     x0, [x29,#24]
   0x000000000040065c <+12>:    add     x0, x29, #0x28
   0x0000000000400660 <+16>:    ldr     x1, [x29,#24]
   0x0000000000400664 <+20>:    bl      0x4004e0 <strcpy@plt>
   0x0000000000400668 <+24>:    nop
   0x000000000040066c <+28>:    ldp     x29, x30, [sp],#48
   0x0000000000400670 <+32>:    ret
End of assembler dump.
```

Breakpoint after `strcpy()`:
```
(gdb) b *0x0000000000400668
Breakpoint 1 at 0x400668
```

Non-overflow:
```
(gdb) r AAAABBBBB
Starting program: /home/yookiterm/azl/bof/stack/stack AAAABBBBB

Breakpoint 1, 0x0000000000400668 in handleData ()
(gdb) x/8xg $sp
0xfffffffff410: 0x0000fffffffff440      0x00000000004006bc
0xfffffffff420: 0x0000fffffffff460      0x0000fffffffff7e5
0xfffffffff430: 0x00000000004006c8      0x4242424241414141
0xfffffffff440: 0x0000ffffffff0042      0x0000ffffb7eaa8a0
```

So, whats the return address? Lets check:


```
(gdb) r AAAAAAABBBBBBBBBCCCCCCCCC
Starting program: /home/yookiterm/azl/bof/stack/stack AAAAAAABBBBBBBBBCCCCCCCCC
Breakpoint 1, 0x0000000000400668 in handleData ()
(gdb) x/8xg $sp
0xfffffffff400: 0x0000fffffffff430      0x00000000004006bc
0xfffffffff410: 0x0000fffffffff450      0x0000fffffffff7d5
0xfffffffff420: 0x00000000004006c8      0x4241414141414141
0xfffffffff430: 0x4242424242424242      0x4343434343434343
(gdb) c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x4343434343434343 in ?? ()
```

What happens? It appears the return address is `0x0000ffffb7eaa8a0`, which points to:

```
(gdb) disas 0x0000ffffb7eaa8a0
Dump of assembler code for function __libc_start_main:
...
0x0000ffffb7eaa88c <+204>:   ldr     w0, [x29,#84]
0x0000ffffb7eaa890 <+208>:   ldr     x2, [x3]
0x0000ffffb7eaa894 <+212>:   ldr     x3, [x29,#72]
0x0000ffffb7eaa898 <+216>:   stp     x6, x5, [x29,#288]
0x0000ffffb7eaa89c <+220>:   blr     x3
0x0000ffffb7eaa8a0 <+224>:   bl      0xffffb7ebef28 <__GI_exit>  # here
0x0000ffffb7eaa8a4 <+228>:   ldr     x2, [x1,#200]
0x0000ffffb7eaa8a8 <+232>:   adrp    x0, 0xffffb7fa1000
0x0000ffffb7eaa8ac <+236>:   ldr     x1, [x29,#88]
0x0000ffffb7eaa8b0 <+240>:   add     x0, x0, #0x128
0x0000ffffb7eaa8b4 <+244>:   ldr     x1, [x1]
```
