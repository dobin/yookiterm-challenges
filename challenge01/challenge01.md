# Introduction to memory layout - variable segment analysis

## Introduction

In this challenge, we have a program which prints the address of various variables
to stdout. Using `readelf`, we will reverse in which ELF sections and segments
these variables are stored.

## Goal

- Learn more about memory layout and ELF
- Get a feeling of useful Linux tools

## Source

File: `~/challenges/challenge01/challenge1.c`
```c
#include <stdio.h>
#include <stdlib.h>

char globalVariable[] = "GlobalVar";
const char globalStaticVariable[] = "GlobalStaticVar";

int main(int argc, char **argv) {
	char *localStackVar = "StackVar";
	char *heapVar = malloc(16);

	printf("Global variable:        %p\n", globalVariable);
	printf("Global static variable: %p\n", globalStaticVariable);
	printf("Stack variable:         %p\n", localStackVar);
	printf("Heap variable:          %p\n", heapVar);
}
```

You can compile it by calling `make` in the folder `~/challenges/challenge01`

## Output

If we execute the program, we get the following output:

```sh
~/challenges/challenge01$ ./challenge01
Global variable:        0x804c020
Global static variable: 0x804a008
Stack variable:         0xffffdd2c
Heap variable:          0x804d1a0
Function:               0x8049172
```


## Analysis

Lets print all sections and segments of the ELF binary:
```sh
root@hlUbuntu32:~/challenges/challenge01# readelf -l -S challenge1
There are 29 section headers, starting at offset 0x37f4:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048194 000194 000013 00   A  0   0  1
  [ 2] .note.gnu.bu[...] NOTE            080481a8 0001a8 000024 00   A  0   0  4
  [ 3] .note.ABI-tag     NOTE            080481cc 0001cc 000020 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ec 0001ec 000020 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          0804820c 00020c 000060 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0804826c 00026c 000053 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          080482c0 0002c0 00000c 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         080482cc 0002cc 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             080482ec 0002ec 000008 08   A  5   0  4
  [10] .rel.plt          REL             080482f4 0002f4 000018 08  AI  5  22  4
  [11] .init             PROGBITS        08049000 001000 000020 00  AX  0   0  4
  [12] .plt              PROGBITS        08049020 001020 000040 04  AX  0   0 16
  [13] .text             PROGBITS        08049060 001060 000275 00  AX  0   0 16
  [14] .fini             PROGBITS        080492d8 0012d8 000014 00  AX  0   0  4
  [15] .rodata           PROGBITS        0804a000 002000 0000a9 00   A  0   0  4
  [16] .eh_frame_hdr     PROGBITS        0804a0ac 0020ac 000054 00   A  0   0  4
  [17] .eh_frame         PROGBITS        0804a100 002100 000160 00   A  0   0  4
  [18] .init_array       INIT_ARRAY      0804bf0c 002f0c 000004 04  WA  0   0  4
  [19] .fini_array       FINI_ARRAY      0804bf10 002f10 000004 04  WA  0   0  4
  [20] .dynamic          DYNAMIC         0804bf14 002f14 0000e8 08  WA  6   0  4
  [21] .got              PROGBITS        0804bffc 002ffc 000004 04  WA  0   0  4
  [22] .got.plt          PROGBITS        0804c000 003000 000018 04  WA  0   0  4
  [23] .data             PROGBITS        0804c018 003018 000012 00  WA  0   0  4
  [24] .bss              NOBITS          0804c02a 00302a 000002 00  WA  0   0  1
  [25] .comment          PROGBITS        00000000 00302a 000027 01  MS  0   0  1
  [26] .symtab           SYMTAB          00000000 003054 000450 10     27  43  4
  [27] .strtab           STRTAB          00000000 0034a4 00024e 00      0   0  1
  [28] .shstrtab         STRTAB          00000000 0036f2 000101 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  p (processor specific)

Elf file type is EXEC (Executable file)
Entry point 0x8049060
There are 11 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00160 0x00160 R   0x4
  INTERP         0x000194 0x08048194 0x08048194 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x0030c 0x0030c R   0x1000
  LOAD           0x001000 0x08049000 0x08049000 0x002ec 0x002ec R E 0x1000
  LOAD           0x002000 0x0804a000 0x0804a000 0x00260 0x00260 R   0x1000
  LOAD           0x002f0c 0x0804bf0c 0x0804bf0c 0x0011e 0x00120 RW  0x1000
  DYNAMIC        0x002f14 0x0804bf14 0x0804bf14 0x000e8 0x000e8 RW  0x4
  NOTE           0x0001a8 0x080481a8 0x080481a8 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x0020ac 0x0804a0ac 0x0804a0ac 0x00054 0x00054 R   0x4
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

### Analyze the Global variable

The address of the global variable is `0x804c020`. If we check the section
headers at the column "Addr", we'll see that this variable is located in the
section with the name `.data` with number 23, which starts at `0x804c018`. `.data` contains
static initialized data and is writeable.

The file offset of `.data` is "0x3018". We can dump it with a tool like `hexdump`, by
using the `s` parameter to skip the same amount of bytes as the offset specifies:

```sh
~/challenges/challenge01$ hexdump -C -s 0x3018 -n 32 challenge01
00003018  00 00 00 00 00 00 00 00  47 6c 6f 62 61 6c 56 61  |........GlobalVa|
00003028  72 00 47 43 43 3a 20 28  44 65 62 69 61 6e 20 31  |r.GCC: (Debian 1|
```

As we can see, the content of the C variable `globalVariable` is written in
the ELF binary: `GlobalVar`.


## Things to think about

* In which section and segment is the variable `globalStaticVariable` stored?
* In which section and segment is the variable `heapVar` stored?
* In which section and segment is the variable `localStackVar` stored?
* Can you locate the content of the variables in the ELF binary? If not, why not?
