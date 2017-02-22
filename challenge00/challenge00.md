# Introduction to memory layout - basic

## Introduction

In this challenge, we will look at some basic Linux tools which display information
about the used memory regions in a program (static analysis) or a process (dynamic analysis).

Tools used:
* file
* readelf
* objdump
* gdb


## Goal

- Learn about memory layout and ELF
- Get a feeling of useful Linux tools


## Source

File: `~/challenges/challenge00/challenge0.c`
```c
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc == 1) {
        printf("Call: %s <name>\n", argv[0]);
        exit(0);
    }

    printf("Hello %s\n", argv[1]);
}
```
You can compile it by calling `make` in the folder `~/challenges/challenge00`


## Static analysis

### file command

The command "file" can be used to get generic information about the executable:

```sh
~/challenges/challenge00# file challenge0          
challenge0: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a8dae60baebe49945ea443d4cc4198b946da27fc, not stripped
```

The binary is therefore:
* 32 bit
* On an little endian machine (`LSB`)
* Intel architecture (Intel 80386 is x86)
* Dynamically linked
* Not stripped


### readelf command

The command "readelf" displays information about the sections and segments of
the program on disk.

Type `readelf -l challenge0`
```sh
~/challenges/challenge00# readelf -l ./challenge0

Elf file type is EXEC (Executable file)
Entry point 0x8048340
There are 9 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x00634 0x00634 R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00122 0x00124 RW  0x1000
  DYNAMIC        0x000f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
  NOTE           0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x00053c 0x0804853c 0x0804853c 0x0002c 0x0002c R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x000f08 0x08049f08 0x08049f08 0x000f8 0x000f8 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00     
   01     .interp
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame
   03     .init_array .fini_array .jcr .dynamic .got .got.plt .data .bss
   04     .dynamic
   05     .note.ABI-tag .note.gnu.build-id
   06     .eh_frame_hdr
   07     
   08     .init_array .fini_array .jcr .dynamic .got
```


### objdump command

Try `objdump -d` to decompile the program:
```sh
~/challenges/challenge00# objdump -d challenge0
challenge0:     file format elf32-i386

Disassembly of section .init:

080482cc <_init>:
 80482cc:       53                      push   %ebx
 80482cd:       83 ec 08                sub    $0x8,%esp
 80482d0:       e8 9b 00 00 00          call   8048370 <__x86.get_pc_thunk.bx>
 80482d5:       81 c3 2b 1d 00 00       add    $0x1d2b,%ebx
 80482db:       8b 83 fc ff ff ff       mov    -0x4(%ebx),%eax
 80482e1:       85 c0                   test   %eax,%eax
 80482e3:       74 05                   je     80482ea <_init+0x1e>
 80482e5:       e8 46 00 00 00          call   8048330 <__libc_start_main@plt+0x10>
 80482ea:       83 c4 08                add    $0x8,%esp
 80482ed:       5b                      pop    %ebx
 80482ee:       c3                      ret    

Disassembly of section .plt:

080482f0 <printf@plt-0x10>:
 80482f0:       ff 35 04 a0 04 08       pushl  0x804a004
 80482f6:       ff 25 08 a0 04 08       jmp    *0x804a008
 80482fc:       00 00                   add    %al,(%eax)
        ...

08048300 <printf@plt>:
 8048300:       ff 25 0c a0 04 08       jmp    *0x804a00c
 8048306:       68 00 00 00 00          push   $0x0
 804830b:       e9 e0 ff ff ff          jmp    80482f0 <_init+0x24>

08048310 <exit@plt>:
 8048310:       ff 25 10 a0 04 08       jmp    *0x804a010
 8048316:       68 08 00 00 00          push   $0x8
 804831b:       e9 d0 ff ff ff          jmp    80482f0 <_init+0x24>

08048320 <__libc_start_main@plt>:
 8048320:       ff 25 14 a0 04 08       jmp    *0x804a014
 8048326:       68 10 00 00 00          push   $0x10
 804832b:       e9 c0 ff ff ff          jmp    80482f0 <_init+0x24>

Disassembly of section .plt.got:

08048330 <.plt.got>:
 8048330:       ff 25 fc 9f 04 08       jmp    *0x8049ffc
 8048336:       66 90                   xchg   %ax,%ax

 Disassembly of section .text:

 08048340 <_start>:
  8048340:       31 ed                   xor    %ebp,%ebp
  8048342:       5e                      pop    %esi
  8048343:       89 e1                   mov    %esp,%ecx
  8048345:       83 e4 f0                and    $0xfffffff0,%esp
  8048348:       50                      push   %eax
  8048349:       54                      push   %esp
  804834a:       52                      push   %edx
  804834b:       68 00 85 04 08          push   $0x8048500
  8048350:       68 a0 84 04 08          push   $0x80484a0
  8048355:       51                      push   %ecx
  8048356:       56                      push   %esi
  8048357:       68 3b 84 04 08          push   $0x804843b
  804835c:       e8 bf ff ff ff          call   8048320 <__libc_start_main@plt>
  8048361:       f4                      hlt    
  8048362:       66 90                   xchg   %ax,%ax
  8048364:       66 90                   xchg   %ax,%ax
  8048366:       66 90                   xchg   %ax,%ax
  8048368:       66 90                   xchg   %ax,%ax
  804836a:       66 90                   xchg   %ax,%ax
  804836c:       66 90                   xchg   %ax,%ax
  804836e:       66 90                   xchg   %ax,%ax

[...]

0804843b <main>:
 804843b:       8d 4c 24 04             lea    0x4(%esp),%ecx
 804843f:       83 e4 f0                and    $0xfffffff0,%esp
 8048442:       ff 71 fc                pushl  -0x4(%ecx)
 8048445:       55                      push   %ebp
 8048446:       89 e5                   mov    %esp,%ebp
 8048448:       51                      push   %ecx
 8048449:       83 ec 04                sub    $0x4,%esp
 804844c:       89 c8                   mov    %ecx,%eax
 804844e:       83 38 01                cmpl   $0x1,(%eax)
 8048451:       75 20                   jne    8048473 <main+0x38>
 8048453:       8b 40 04                mov    0x4(%eax),%eax
 8048456:       8b 00                   mov    (%eax),%eax
 8048458:       83 ec 08                sub    $0x8,%esp
 804845b:       50                      push   %eax
 804845c:       68 20 85 04 08          push   $0x8048520
 8048461:       e8 9a fe ff ff          call   8048300 <printf@plt>
 8048466:       83 c4 10                add    $0x10,%esp
 8048469:       83 ec 0c                sub    $0xc,%esp
 804846c:       6a 00                   push   $0x0
 804846e:       e8 9d fe ff ff          call   8048310 <exit@plt>
 8048473:       8b 40 04                mov    0x4(%eax),%eax
 8048476:       83 c0 04                add    $0x4,%eax
 8048479:       8b 00                   mov    (%eax),%eax
 804847b:       83 ec 08                sub    $0x8,%esp
 804847e:       50                      push   %eax
 804847f:       68 31 85 04 08          push   $0x8048531
 8048484:       e8 77 fe ff ff          call   8048300 <printf@plt>
 8048489:       83 c4 10                add    $0x10,%esp
 804848c:       b8 00 00 00 00          mov    $0x0,%eax
 8048491:       8b 4d fc                mov    -0x4(%ebp),%ecx
 8048494:       c9                      leave  
 8048495:       8d 61 fc                lea    -0x4(%ecx),%esp
 8048498:       c3                      ret    
 8048499:       66 90                   xchg   %ax,%ax
 804849b:       66 90                   xchg   %ax,%ax
 804849d:       66 90                   xchg   %ax,%ax
 804849f:       90                      nop

[...]
```


## Dynamic analysis

Let's debug the binary using gdb

```sh
~/challenges/challenge00# gdb -q ./challenge0
Reading symbols from ./challenge0...(no debugging symbols found)...done.
gdb-peda$ run test
Starting program: /root/challenges/challenge00/challenge0 test
Hello test
```

Now let's disassemble main with the `disass` command:
```sh
gdb-peda$ disass main
Dump of assembler code for function main:
   0x0804843b <+0>:     lea    ecx,[esp+0x4]
   0x0804843f <+4>:     and    esp,0xfffffff0
   0x08048442 <+7>:     push   DWORD PTR [ecx-0x4]
   0x08048445 <+10>:    push   ebp
   0x08048446 <+11>:    mov    ebp,esp
   0x08048448 <+13>:    push   ecx
   0x08048449 <+14>:    sub    esp,0x4
   0x0804844c <+17>:    mov    eax,ecx
   0x0804844e <+19>:    cmp    DWORD PTR [eax],0x1
   0x08048451 <+22>:    jne    0x8048473 <main+56>
   0x08048453 <+24>:    mov    eax,DWORD PTR [eax+0x4]
   0x08048456 <+27>:    mov    eax,DWORD PTR [eax]
   0x08048458 <+29>:    sub    esp,0x8
   0x0804845b <+32>:    push   eax
   0x0804845c <+33>:    push   0x8048520
   0x08048461 <+38>:    call   0x8048300 <printf@plt>
   0x08048466 <+43>:    add    esp,0x10
   0x08048469 <+46>:    sub    esp,0xc
   0x0804846c <+49>:    push   0x0
   0x0804846e <+51>:    call   0x8048310 <exit@plt>
   0x08048473 <+56>:    mov    eax,DWORD PTR [eax+0x4]
   0x08048476 <+59>:    add    eax,0x4
   0x08048479 <+62>:    mov    eax,DWORD PTR [eax]
   0x0804847b <+64>:    sub    esp,0x8
   0x0804847e <+67>:    push   eax
   0x0804847f <+68>:    push   0x8048531
   0x08048484 <+73>:    call   0x8048300 <printf@plt>
   0x08048489 <+78>:    add    esp,0x10
   0x0804848c <+81>:    mov    eax,0x0
   0x08048491 <+86>:    mov    ecx,DWORD PTR [ebp-0x4]
   0x08048494 <+89>:    leave  
   0x08048495 <+90>:    lea    esp,[ecx-0x4]
   0x08048498 <+93>:    ret    
End of assembler dump.
```

We can also show the memory regions with the `info `. But first, lets set a
breakpoint on the `main` function, and start the program with `run`
```sh
gdb-peda$ b *main
Breakpoint 1 at 0x804843b
gdb-peda$ run
Starting program: /root/challenges/challenge00/challenge0

 [----------------------------------registers-----------------------------------]
EAX: 0xf7fccddc --> 0xffffd71c --> 0xffffd866 ("TERM=xterm")
EBX: 0x0
ECX: 0x49435093
EDX: 0xffffd6a4 --> 0x0
ESI: 0xf7fcb000 --> 0x1b1db0
EDI: 0xf7fcb000 --> 0x1b1db0
EBP: 0x0
ESP: 0xffffd67c --> 0xf7e31637 (<__libc_start_main+247>:        add    esp,0x10)
EIP: 0x804843b (<main>: lea    ecx,[esp+0x4])
EFLAGS: 0x292 (carry parity ADJUST zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048432 <frame_dummy+34>:  add    esp,0x10
   0x8048435 <frame_dummy+37>:  leave
   0x8048436 <frame_dummy+38>:  jmp    0x80483b0 <register_tm_clones>
=> 0x804843b <main>:    lea    ecx,[esp+0x4]
   0x804843f <main+4>:  and    esp,0xfffffff0
   0x8048442 <main+7>:  push   DWORD PTR [ecx-0x4]
   0x8048445 <main+10>: push   ebp
   0x8048446 <main+11>: mov    ebp,esp
[------------------------------------stack-------------------------------------]
0000| 0xffffd67c --> 0xf7e31637 (<__libc_start_main+247>:       add    esp,0x10)
0004| 0xffffd680 --> 0x1
0008| 0xffffd684 --> 0xffffd714 --> 0xffffd83f ("/root/challenges/challenge00/challenge0")
0012| 0xffffd688 --> 0xffffd71c --> 0xffffd866 ("TERM=xterm")
0016| 0xffffd68c --> 0x0
0020| 0xffffd690 --> 0x0
0024| 0xffffd694 --> 0x0
0028| 0xffffd698 --> 0xf7fcb000 --> 0x1b1db0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x0804843b in main ()
```


By using `info proc mappings`, we can see the currently used memory mappings:
```sh
gdb-peda$ info proc mappings
process 394
Mapped address spaces:

        Start Addr   End Addr       Size     Offset objfile
         0x8048000  0x8049000     0x1000        0x0 /root/challenges/challenge00/challenge0
         0x8049000  0x804a000     0x1000        0x0 /root/challenges/challenge00/challenge0
         0x804a000  0x804b000     0x1000     0x1000 /root/challenges/challenge00/challenge0
        0xf7e19000 0xf7fc8000   0x1af000        0x0 /lib/i386-linux-gnu/libc-2.23.so
        0xf7fc8000 0xf7fc9000     0x1000   0x1af000 /lib/i386-linux-gnu/libc-2.23.so
        0xf7fc9000 0xf7fcb000     0x2000   0x1af000 /lib/i386-linux-gnu/libc-2.23.so
        0xf7fcb000 0xf7fcc000     0x1000   0x1b1000 /lib/i386-linux-gnu/libc-2.23.so
        0xf7fcc000 0xf7fcf000     0x3000        0x0
        0xf7fd4000 0xf7fd6000     0x2000        0x0
        0xf7fd6000 0xf7fd8000     0x2000        0x0 [vvar]
        0xf7fd8000 0xf7fd9000     0x1000        0x0 [vdso]
        0xf7fd9000 0xf7ffb000    0x22000        0x0 /lib/i386-linux-gnu/ld-2.23.so
        0xf7ffb000 0xf7ffc000     0x1000        0x0
        0xf7ffc000 0xf7ffd000     0x1000    0x22000 /lib/i386-linux-gnu/ld-2.23.so
        0xf7ffd000 0xf7ffe000     0x1000    0x23000 /lib/i386-linux-gnu/ld-2.23.so
        0xfffdd000 0xffffe000    0x21000        0x0 [stack]
```

The same information is accessible via the proc filesystem. You'll have to find
the process id (pid) of the process. Also note that the process has to exist.
We already started the process above with `run`, and stopped it with the breakpoint at `main`.
The process id is 394. We can directly execute bash commands in GDB with `! <command>`, or just use
a second terminal.

```sh
gdb-peda$ ! cat /proc/394/maps
08048000-08049000 r-xp 00000000 00:2d 32791          /root/challenges/challenge00/challenge0
08049000-0804a000 r--p 00000000 00:2d 32791          /root/challenges/challenge00/challenge0
0804a000-0804b000 rw-p 00001000 00:2d 32791          /root/challenges/challenge00/challenge0
f7e19000-f7fc8000 r-xp 00000000 00:2d 14339          /lib/i386-linux-gnu/libc-2.23.so
f7fc8000-f7fc9000 ---p 001af000 00:2d 14339          /lib/i386-linux-gnu/libc-2.23.so
f7fc9000-f7fcb000 r--p 001af000 00:2d 14339          /lib/i386-linux-gnu/libc-2.23.so
f7fcb000-f7fcc000 rw-p 001b1000 00:2d 14339          /lib/i386-linux-gnu/libc-2.23.so
f7fcc000-f7fcf000 rw-p 00000000 00:00 0
f7fd4000-f7fd6000 rw-p 00000000 00:00 0
f7fd6000-f7fd8000 r--p 00000000 00:00 0              [vvar]
f7fd8000-f7fd9000 r-xp 00000000 00:00 0              [vdso]
f7fd9000-f7ffb000 r-xp 00000000 00:2d 14351          /lib/i386-linux-gnu/ld-2.23.so
f7ffb000-f7ffc000 rw-p 00000000 00:00 0
f7ffc000-f7ffd000 r--p 00022000 00:2d 14351          /lib/i386-linux-gnu/ld-2.23.so
f7ffd000-f7ffe000 rw-p 00023000 00:2d 14351          /lib/i386-linux-gnu/ld-2.23.so
fffdd000-ffffe000 rw-p 00000000 00:00 0              [stack]

```


## Questions

### Main questions

* What is the address of the code section?
* Where does the heap start?
* Where does the stack start? Are you sure?

### Secondary questions

Try this challenge on a 64 bit system.

* What is the address of the code section?
* Where does the heap start?
* Where does the stack start?
