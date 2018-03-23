# C buffer analysis - with debugging

## Introduction

We have a vulnerable program which allows us to perform out-of-bound reads.
By debugging and analyzing it we will look at internal stack data of the process by
supplying adequate program inputs.


## Goal

* Understand C arrays by misusing them
* Get comfortable with gdb
* Deeper understanding of the stack

## Source

File: `~/challenges/challenge08/challenge8.c`
```c
#include <stdio.h>

void main(void) {
        int array[5] = { 1, 2, 3, 4, 5};
        printf("Number at index 4: 0x%x\n", array[4]);
        printf("Number at index 5: 0x%x\n", array[5]);
}
```

You can compile it by calling `make` in the folder `~/challenges/challenge08`

## Execution

Lets execute the binary:

```sh
root@hlUbuntu32:~/challenges/challenge08# ./challenge8
Number at index 4: 0x5
Number at index 5: 0xf7fcb3dc
```

The value at index 4 is as expected 0x5. But the value at index 5 seems to be arbitrary or
random. Index 5 is also the 6th entry of the array with size 5. Letrs try to identify
what this value `0xf7fcb3dc` depicts.


## Debugging



Lets debug the binary. Start gdb, and disas the `main` function:

```
root@hlUbuntu32:~/challenges/challenge08# gdb -q challenge8
Reading symbols from challenge8...(no debugging symbols found)...done.
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0804840b <+0>:     lea    ecx,[esp+0x4]
   0x0804840f <+4>:     and    esp,0xfffffff0
   0x08048412 <+7>:     push   DWORD PTR [ecx-0x4]
   0x08048415 <+10>:    push   ebp
   0x08048416 <+11>:    mov    ebp,esp
   0x08048418 <+13>:    push   ecx
   0x08048419 <+14>:    sub    esp,0x24
   0x0804841c <+17>:    mov    DWORD PTR [ebp-0x1c],0x1
   0x08048423 <+24>:    mov    DWORD PTR [ebp-0x18],0x2
   0x0804842a <+31>:    mov    DWORD PTR [ebp-0x14],0x3
   0x08048431 <+38>:    mov    DWORD PTR [ebp-0x10],0x4
   0x08048438 <+45>:    mov    DWORD PTR [ebp-0xc],0x5
   0x0804843f <+52>:    mov    eax,DWORD PTR [ebp-0xc]
   0x08048442 <+55>:    sub    esp,0x8
   0x08048445 <+58>:    push   eax
   0x08048446 <+59>:    push   0x80484f0
   0x0804844b <+64>:    call   0x80482e0 <printf@plt>
   0x08048450 <+69>:    add    esp,0x10
   0x08048453 <+72>:    mov    eax,DWORD PTR [ebp-0x8]
   0x08048456 <+75>:    sub    esp,0x8
   0x08048459 <+78>:    push   eax
   0x0804845a <+79>:    push   0x8048509
   0x0804845f <+84>:    call   0x80482e0 <printf@plt>
   0x08048464 <+89>:    add    esp,0x10
   0x08048467 <+92>:    nop
   0x08048468 <+93>:    mov    ecx,DWORD PTR [ebp-0x4]
   0x0804846b <+96>:    leave
   0x0804846c <+97>:    lea    esp,[ecx-0x4]
   0x0804846f <+100>:   ret
End of assembler dump.
```

We want to break before the 2nd `printf` is called, therefore at address `0x0804845f`, and
run the program:

```
gdb-peda$ b *0x0804845f
Breakpoint 1 at 0x804845f
gdb-peda$ r
Starting program: /root/challenges/challenge08/challenge8
Number at index 4: 0x5

[----------------------------------registers-----------------------------------]
EAX: 0xf7fcb3dc --> 0xf7fcc1e0 --> 0x0
EBX: 0x0
ECX: 0x7fffffe9
EDX: 0xf7fcc870 --> 0x0
ESI: 0xf7fcb000 --> 0x1b1db0
EDI: 0xf7fcb000 --> 0x1b1db0
EBP: 0xffffd668 --> 0x0
ESP: 0xffffd630 --> 0x8048509 ("Number at index 5: 0x%x\n")
EIP: 0x804845f (<main+84>:      call   0x80482e0 <printf@plt>)
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048456 <main+75>: sub    esp,0x8
   0x8048459 <main+78>: push   eax
   0x804845a <main+79>: push   0x8048509
=> 0x804845f <main+84>: call   0x80482e0 <printf@plt>
   0x8048464 <main+89>: add    esp,0x10
   0x8048467 <main+92>: nop
   0x8048468 <main+93>: mov    ecx,DWORD PTR [ebp-0x4]
   0x804846b <main+96>: leave
Guessed arguments:
arg[0]: 0x8048509 ("Number at index 5: 0x%x\n")
arg[1]: 0xf7fcb3dc --> 0xf7fcc1e0 --> 0x0
[------------------------------------stack-------------------------------------]
0000| 0xffffd630 --> 0x8048509 ("Number at index 5: 0x%x\n")
0004| 0xffffd634 --> 0xf7fcb3dc --> 0xf7fcc1e0 --> 0x0
0008| 0xffffd638 --> 0x0
0012| 0xffffd63c --> 0xf7e3132a (<init_cacheinfo+666>:  mov    DWORD PTR [esp+0xc],0x2)
0016| 0xffffd640 --> 0x1
0020| 0xffffd644 --> 0x0
0024| 0xffffd648 --> 0xf7e47a30 (<__new_exitfn+16>:     add    ebx,0x1835d0)
0028| 0xffffd64c --> 0x1
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804845f in main ()
```

We stopped execution before the printf() executed. Lets examine the stack:

```
gdb-peda$ x/32x $esp
0xffffd630:     0x08048529      0xf7fcb3dc      0x00000000      0xf7e3132a
0xffffd640:     0x00000001      0x00000000      0xf7e47a30      0x00000001
0xffffd650:     0x00000002      0x00000003      0x00000004      0x00000005
0xffffd660:     0xf7fcb3dc      0xffffd680      0x00000000      0xf7e31637
0xffffd670:     0xf7fcb000      0xf7fcb000      0x00000000      0xf7e31637
0xffffd680:     0x00000001      0xffffd714      0xffffd71c      0x00000000
0xffffd690:     0x00000000      0x00000000      0xf7fcb000      0xf7ffdc04
0xffffd6a0:     0xf7ffd000      0x00000000      0xf7fcb000      0xf7fcb000
gdb-peda$
```

Seems like the value `0xf7fcb3dc` is located on the stack, right after the array
(fourth line, first entry).


## Questions

* What was the error of the programmer?
* If we would instead of `array[5]` print `array[6]`, which value would appear?
  * Note: If you want to test your assumption, make sure to execute the binary in gdb. GDB- and non-GDB execution have a small difference in the stack layout.
