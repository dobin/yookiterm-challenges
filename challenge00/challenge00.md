# Introduction to memory layout - analysis tools

## Introduction

In this challenge, we will look at some basic Linux tools which display information
about the used memory regions in a program (static analysis) or a process (dynamic analysis).

Tools used:
* file
* readelf
* objdump
* gdb


## Goal

* Learn about memory layout and ELF
* Get a feeling of useful Linux tools


## Source

* Source directory: `~/challenges/challenge00/`
* Source files: [challenge00](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge00)

You can compile it by calling `make` in the folder `~/challenges/challenge00`

Source:
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


## Static analysis

### file command

The command `file` can be used to get generic information about the executable:

```sh
~/challenges/challenge00# file challenge00
challenge00: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a8dae60baebe49945ea443d4cc4198b946da27fc, not stripped
```

The binary is therefore:
* 32 bit
* On an little endian machine (`LSB`)
* Intel architecture (Intel 80386 is x86)
* Dynamically linked (not static, it depends on shared libraries)
* Not stripped (debug symbols are still there)


### readelf command

The command `readelf` displays information about the sections and segments of
the program on disk:

```sh
~/challenges/challenge00$ readelf -l challenge00

Elf file type is EXEC (Executable file)
Entry point 0x8049060
There are 11 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00160 0x00160 R   0x4
  INTERP         0x000194 0x08048194 0x08048194 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x0030c 0x0030c R   0x1000
  LOAD           0x001000 0x08049000 0x08049000 0x0025c 0x0025c R E 0x1000
  LOAD           0x002000 0x0804a000 0x0804a000 0x00190 0x00190 R   0x1000
  LOAD           0x002f0c 0x0804bf0c 0x0804bf0c 0x00114 0x00118 RW  0x1000
  DYNAMIC        0x002f14 0x0804bf14 0x0804bf14 0x000e8 0x000e8 RW  0x4
  NOTE           0x0001a8 0x080481a8 0x080481a8 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x002024 0x0804a024 0x0804a024 0x00044 0x00044 R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x002f0c 0x0804bf0c 0x0804bf0c 0x000f4 0x000f4 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.gnu.build-id .note.ABI-tag .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt
   03     .init .plt .text .fini
   04     .rodata .eh_frame_hdr .eh_frame
   05     .init_array .fini_array .dynamic .got .got.plt .data .bss
   06     .dynamic
   07     .note.gnu.build-id .note.ABI-tag
   08     .eh_frame_hdr
   09
   10     .init_array .fini_array .dynamic .got
```


### objdump command

The command `objdump -d` will decompile the program on disk:

```sh
~/challenges/challenge00# objdump -d challenge00 | less
challenge00:     file format elf32-i386


Disassembly of section .init:

08049000 <_init>:
 8049000:       53                      push   %ebx
 8049001:       83 ec 08                sub    $0x8,%esp
 8049004:       e8 a7 00 00 00          call   80490b0 <__x86.get_pc_thunk.bx>
 8049009:       81 c3 f7 2f 00 00       add    $0x2ff7,%ebx
 804900f:       8b 83 fc ff ff ff       mov    -0x4(%ebx),%eax
 8049015:       85 c0                   test   %eax,%eax
 8049017:       74 02                   je     804901b <_init+0x1b>
 8049019:       ff d0                   call   *%eax
 804901b:       83 c4 08                add    $0x8,%esp
 804901e:       5b                      pop    %ebx
 804901f:       c3                      ret

Disassembly of section .plt:

08049020 <.plt>:
 8049020:       ff 35 04 c0 04 08       pushl  0x804c004
 8049026:       ff 25 08 c0 04 08       jmp    *0x804c008
 804902c:       00 00                   add    %al,(%eax)
        ...

08049030 <printf@plt>:
 8049030:       ff 25 0c c0 04 08       jmp    *0x804c00c
 8049036:       68 00 00 00 00          push   $0x0
 804903b:       e9 e0 ff ff ff          jmp    8049020 <.plt>

08049040 <exit@plt>:
 8049040:       ff 25 10 c0 04 08       jmp    *0x804c010
 8049046:       68 08 00 00 00          push   $0x8
 804904b:       e9 d0 ff ff ff          jmp    8049020 <.plt>

08049050 <__libc_start_main@plt>:
 8049050:       ff 25 14 c0 04 08       jmp    *0x804c014
 8049056:       68 10 00 00 00          push   $0x10
 804905b:       e9 c0 ff ff ff          jmp    8049020 <.plt>

Disassembly of section .text:

08049060 <_start>:
 8049060:       31 ed                   xor    %ebp,%ebp
 8049062:       5e                      pop    %esi
 8049063:       89 e1                   mov    %esp,%ecx
 8049065:       83 e4 f0                and    $0xfffffff0,%esp
 8049068:       50                      push   %eax
[...]
```


## Dynamic analysis

Let's debug the binary using GDB debugger:

```sh
~/challenges/challenge00$ gdb -q challenge00
Reading symbols from challenge00...
gef➤  run Argument1
Starting program: /root/challenges/challenge00/challenge00 Argument1
Hello Argument1
[Inferior 1 (process 127) exited normally]
gef➤  quit
~/challenges/challenge00$
```

Now let's disassemble main with the `disass` command. This is basically the same as using `objdump -d`:
```sh
gef➤  disas main
Dump of assembler code for function main:
   0x08049172 <+0>:     lea    ecx,[esp+0x4]
   0x08049176 <+4>:     and    esp,0xfffffff0
   0x08049179 <+7>:     push   DWORD PTR [ecx-0x4]
   0x0804917c <+10>:    push   ebp
   0x0804917d <+11>:    mov    ebp,esp
   0x0804917f <+13>:    push   ecx
   0x08049180 <+14>:    sub    esp,0x4
   0x08049183 <+17>:    mov    eax,ecx
   0x08049185 <+19>:    cmp    DWORD PTR [eax],0x1
   0x08049188 <+22>:    jne    0x80491aa <main+56>
   0x0804918a <+24>:    mov    eax,DWORD PTR [eax+0x4]
   0x0804918d <+27>:    mov    eax,DWORD PTR [eax]
   0x0804918f <+29>:    sub    esp,0x8
   0x08049192 <+32>:    push   eax
   0x08049193 <+33>:    push   0x804a008
   0x08049198 <+38>:    call   0x8049030 <printf@plt>
   0x0804919d <+43>:    add    esp,0x10
   0x080491a0 <+46>:    sub    esp,0xc
   0x080491a3 <+49>:    push   0x0
   0x080491a5 <+51>:    call   0x8049040 <exit@plt>
   0x080491aa <+56>:    mov    eax,DWORD PTR [eax+0x4]
   0x080491ad <+59>:    add    eax,0x4
   0x080491b0 <+62>:    mov    eax,DWORD PTR [eax]
   0x080491b2 <+64>:    sub    esp,0x8
   0x080491b5 <+67>:    push   eax
   0x080491b6 <+68>:    push   0x804a019
   0x080491bb <+73>:    call   0x8049030 <printf@plt>
   0x080491c0 <+78>:    add    esp,0x10
   0x080491c3 <+81>:    mov    eax,0x0
   0x080491c8 <+86>:    mov    ecx,DWORD PTR [ebp-0x4]
   0x080491cb <+89>:    leave
   0x080491cc <+90>:    lea    esp,[ecx-0x4]
   0x080491cf <+93>:    ret
End of assembler dump.
```

Lets set a breakpoint on the `main` function, and start the program so we have a running process, 
and not just a static ELF file:

```sh
gef➤  b *main
Breakpoint 1 at 0x8049172: file challenge00.c, line 4.
gef➤  r Testing
Starting program: /root/challenges/challenge00/challenge00 Testing

Breakpoint 1, main (argc=0x2, argv=0xffffdda4) at challenge00.c:4
4       int main(int argc, char **argv) {
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────── source:challenge00.c+4 ────
      3
         // argc=0x2, argv=0xffffdd04  →  [...]  →  "/root/challenges/challenge00/challenge00"
 →    4  int main(int argc, char **argv) {
      5      if (argc == 1) {
───────────────────────────────────────────────────────────────────────────────────────── registers ────
$eax   : 0xf7fc3ae8  →  0xffffddb0  →  0xffffdee7  →  "USER=root"
$ebx   : 0x0
$ecx   : 0x206a1cc8
$edx   : 0xffffdd34  →  0x00000000
$esp   : 0xffffdcfc  →  0xf7dfae46  →  <__libc_start_main+262> add esp, 0x10
$ebp   : 0x0
$esi   : 0xf7fc1000  →  0x001e4d6c
$edi   : 0xf7fc1000  →  0x001e4d6c
$eip   : 0x8049172  →  <main+0> lea ecx, [esp+0x4]
─────────────────────────────────────────────────────────────────────────────────────── code:x86:32 ────
    0x8049168 <__do_global_dtors_aux+40> lea    esi, [esi+eiz*1+0x0]
    0x804916f <__do_global_dtors_aux+47> nop
    0x8049170 <frame_dummy+0>  jmp    0x8049100 <register_tm_clones>
 →  0x8049172 <main+0>         lea    ecx, [esp+0x4]
    0x8049176 <main+4>         and    esp, 0xfffffff0
─────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge00", stopped 0x8049172 in main (), reason: BREAKPOINT
────────────────────────────────────────────────────────────────────────────────────────────────────────
```

The process is stopped, and we are able to inspect all its data, including registers and RAM.

Take a moment to orient yourself in the output. From top to bottom we can see: 
* That we reached Breakpoint 1
* The source code of the instruction we are currently stopped at
* Most register values, and where they point to
* The assembly instructions, and where we stopped at (here at main+0, indicated by an arrow)
* GDB Status output


### Register

To display the registers again, or individual ones:
```
gef➤  info register
eax            0xf7fc3ae8          0xf7fc3ae8
ecx            0x206a1cc8          0x206a1cc8
edx            0xffffdd34          0xffffdd34
ebx            0x0                 0x0
esp            0xffffdcfc          0xffffdcfc
ebp            0x0                 0x0
esi            0xf7fc1000          0xf7fc1000
edi            0xf7fc1000          0xf7fc1000
eip            0x8049172           0x8049172 <main>
eflags         0x246               [ PF ZF IF ]
cs             0x23                0x23
ss             0x2b                0x2b
ds             0x2b                0x2b
es             0x2b                0x2b
fs             0x0                 0x0
gs             0x63                0x63
gef➤  i r eax
eax            0xf7fc3ae8          0xf7fc3ae8
```


### Memory / RAM

Lets have a look at the stack, referenced via register `$esp`:

```
gef➤  x/16dx $esp
0xffffdcfc:     0xf7dfae46      0x00000002      0xffffdda4      0xffffddb0
0xffffdd0c:     0xffffdd34      0xffffdd44      0xf7ffdb40      0xf7fca410
0xffffdd1c:     0xf7fc1000      0x00000001      0x00000000      0xffffdd88
0xffffdd2c:     0x00000000      0xf7ffd000      0x00000000      0xf7fc1000
```

This e`X`amines `16` elements of type `d`ouble (4 bytes) and displays it as he`x` number starting from memory address in register `$esp`.


### Memory Mapping

By using `vmmap`, we can see the currently used memory mappings:
```sh
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start      End        Offset     Perm Path
0x8048000 0x8049000 0x000000 r-- /root/challenges/challenge00/challenge00
0x8049000 0x804a000 0x001000 r-x /root/challenges/challenge00/challenge00
0x804a000 0x804b000 0x002000 r-- /root/challenges/challenge00/challenge00
0x804b000 0x804c000 0x002000 r-- /root/challenges/challenge00/challenge00
0x804c000 0x804d000 0x003000 rw- /root/challenges/challenge00/challenge00
0xf7ddc000 0xf7df9000 0x000000 r-- /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7df9000 0xf7f4e000 0x01d000 r-x /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7f4e000 0xf7fbf000 0x172000 r-- /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fbf000 0xf7fc1000 0x1e2000 r-- /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fc1000 0xf7fc3000 0x1e4000 rw- /usr/lib/i386-linux-gnu/libc-2.31.so
0xf7fc3000 0xf7fc5000 0x000000 rw-
0xf7fca000 0xf7fcc000 0x000000 rw-
0xf7fcc000 0xf7fd0000 0x000000 r-- [vvar]
0xf7fd0000 0xf7fd2000 0x000000 r-x [vdso]
0xf7fd2000 0xf7fd3000 0x000000 r-- /usr/lib/i386-linux-gnu/ld-2.31.so
0xf7fd3000 0xf7ff0000 0x001000 r-x /usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ff0000 0xf7ffb000 0x01e000 r-- /usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ffc000 0xf7ffd000 0x029000 r-- /usr/lib/i386-linux-gnu/ld-2.31.so
0xf7ffd000 0xf7ffe000 0x02a000 rw- /usr/lib/i386-linux-gnu/ld-2.31.so
0xfffdd000 0xffffe000 0x000000 rw- [stack]

```

The same information is accessible via the proc filesystem. You'll have to find
the process id (pid) of the process. Also note that the process has to exist.
We already started the process above with `run`, and stopped it with the breakpoint at `main`.
The process id is 394. We can directly execute bash commands in GDB with `! <command>`, or just use
a second terminal.

```sh
gef➤  ! cat /proc/239/maps
08048000-08049000 r--p 00000000 00:44 137273                             /root/challenges/challenge00/challenge00
08049000-0804a000 r-xp 00001000 00:44 137273                             /root/challenges/challenge00/challenge00
0804a000-0804b000 r--p 00002000 00:44 137273                             /root/challenges/challenge00/challenge00
0804b000-0804c000 r--p 00002000 00:44 137273                             /root/challenges/challenge00/challenge00
0804c000-0804d000 rw-p 00003000 00:44 137273                             /root/challenges/challenge00/challenge00
f7ddc000-f7df9000 r--p 00000000 00:44 1081                               /usr/lib/i386-linux-gnu/libc-2.31.so
f7df9000-f7f4e000 r-xp 0001d000 00:44 1081                               /usr/lib/i386-linux-gnu/libc-2.31.so
f7f4e000-f7fbf000 r--p 00172000 00:44 1081                               /usr/lib/i386-linux-gnu/libc-2.31.so
f7fbf000-f7fc1000 r--p 001e2000 00:44 1081                               /usr/lib/i386-linux-gnu/libc-2.31.so
f7fc1000-f7fc3000 rw-p 001e4000 00:44 1081                               /usr/lib/i386-linux-gnu/libc-2.31.so
f7fc3000-f7fc5000 rw-p 00000000 00:00 0
f7fca000-f7fcc000 rw-p 00000000 00:00 0
f7fcc000-f7fd0000 r--p 00000000 00:00 0                                  [vvar]
f7fd0000-f7fd2000 r-xp 00000000 00:00 0                                  [vdso]
f7fd2000-f7fd3000 r--p 00000000 00:44 1040                               /usr/lib/i386-linux-gnu/ld-2.31.so
f7fd3000-f7ff0000 r-xp 00001000 00:44 1040                               /usr/lib/i386-linux-gnu/ld-2.31.so
f7ff0000-f7ffb000 r--p 0001e000 00:44 1040                               /usr/lib/i386-linux-gnu/ld-2.31.so
f7ffc000-f7ffd000 r--p 00029000 00:44 1040                               /usr/lib/i386-linux-gnu/ld-2.31.so
f7ffd000-f7ffe000 rw-p 0002a000 00:44 1040                               /usr/lib/i386-linux-gnu/ld-2.31.so
fffdd000-ffffe000 rw-p 00000000 00:00 0                                  [stack]
```


## Things to think about

* The difference between a program (on-disk) and a process (in-memory)
