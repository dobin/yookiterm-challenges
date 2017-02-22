# Introduction to memory layout - advanced

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

	printf("Global variable:        0x%p\n", globalVariable);
	printf("Global static variable: 0x%p\n", globalStaticVariable);
	printf("Stack variable:         0x%p\n", localStackVar);
	printf("Heap variable:          0x%p\n", heapVar);
}
```

You can compile it by calling `make` in the folder `~/challenges/challenge01`

## Output

If we execute the program, we get the following output:

```sh
root@hlUbuntu32:~/challenges/challenge01# ./challenge1
Global variable:        0x0x804a020
Global static variable: 0x0x8048540
Stack variable:         0x0x8048550
Heap variable:          0x0x8960008
```


## Analysis

Lets print all sections and segments of the ELF binary:
```sh
root@hlUbuntu32:~/challenges/challenge01# readelf -l -S challenge0
There are 31 section headers, starting at offset 0x1854:

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .interp           PROGBITS        08048154 000154 000013 00   A  0   0  1
  [ 2] .note.ABI-tag     NOTE            08048168 000168 000020 00   A  0   0  4
  [ 3] .note.gnu.build-i NOTE            08048188 000188 000024 00   A  0   0  4
  [ 4] .gnu.hash         GNU_HASH        080481ac 0001ac 000020 04   A  5   0  4
  [ 5] .dynsym           DYNSYM          080481cc 0001cc 000060 10   A  6   1  4
  [ 6] .dynstr           STRTAB          0804822c 00022c 000053 00   A  0   0  1
  [ 7] .gnu.version      VERSYM          08048280 000280 00000c 02   A  5   0  2
  [ 8] .gnu.version_r    VERNEED         0804828c 00028c 000020 00   A  6   1  4
  [ 9] .rel.dyn          REL             080482ac 0002ac 000008 08   A  5   0  4
  [10] .rel.plt          REL             080482b4 0002b4 000018 08  AI  5  24  4
  [11] .init             PROGBITS        080482cc 0002cc 000023 00  AX  0   0  4
  [12] .plt              PROGBITS        080482f0 0002f0 000040 04  AX  0   0 16
  [13] .plt.got          PROGBITS        08048330 000330 000008 00  AX  0   0  8
  [14] .text             PROGBITS        08048340 000340 0001e2 00  AX  0   0 16
  [15] .fini             PROGBITS        08048524 000524 000014 00  AX  0   0  4
  [16] .rodata           PROGBITS        08048538 000538 000099 00   A  0   0  4
  [17] .eh_frame_hdr     PROGBITS        080485d4 0005d4 00002c 00   A  0   0  4
  [18] .eh_frame         PROGBITS        08048600 000600 0000cc 00   A  0   0  4
  [19] .init_array       INIT_ARRAY      08049f08 000f08 000004 00  WA  0   0  4
  [20] .fini_array       FINI_ARRAY      08049f0c 000f0c 000004 00  WA  0   0  4
  [21] .jcr              PROGBITS        08049f10 000f10 000004 00  WA  0   0  4
  [22] .dynamic          DYNAMIC         08049f14 000f14 0000e8 08  WA  6   0  4
  [23] .got              PROGBITS        08049ffc 000ffc 000004 04  WA  0   0  4
  [24] .got.plt          PROGBITS        0804a000 001000 000018 04  WA  0   0  4
  [25] .data             PROGBITS        0804a018 001018 000012 00  WA  0   0  4
  [26] .bss              NOBITS          0804a02a 00102a 000002 00  WA  0   0  1
  [27] .comment          PROGBITS        00000000 00102a 000034 01  MS  0   0  1
  [28] .shstrtab         STRTAB          00000000 00174a 00010a 00      0   0  1
  [29] .symtab           SYMTAB          00000000 001060 000480 10     30  47  4
  [30] .strtab           STRTAB          00000000 0014e0 00026a 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings)
  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
  O (extra OS processing required) o (OS specific), p (processor specific)

Elf file type is EXEC (Executable file)
Entry point 0x8048340
There are 9 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x08048034 0x08048034 0x00120 0x00120 R E 0x4
  INTERP         0x000154 0x08048154 0x08048154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x08048000 0x08048000 0x006cc 0x006cc R E 0x1000
  LOAD           0x000f08 0x08049f08 0x08049f08 0x00122 0x00124 RW  0x1000
  DYNAMIC        0x000f14 0x08049f14 0x08049f14 0x000e8 0x000e8 RW  0x4
  NOTE           0x000168 0x08048168 0x08048168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x0005d4 0x080485d4 0x080485d4 0x0002c 0x0002c R   0x4
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

### Analyze the Global variable

The address of the global variable is `0x804a020`. If we check the section
headers at the column "Addr", we'll see that this variable is located in the
section with the name `.data` with number 25, which starts at `0x804a018`. `.data` contains
static initialized data and is writeable.

The file offset of `.data` is "0x1018". We can dump it with a tool like `hexdump`, by
using the `s` parameter to skip the same amount of bytes as the offset specifies:

```sh
root@hlUbuntu32:~/challenges/challenge01# hexdump -C -s 0x1018 -n 32 challenge1
00001018  00 00 00 00 00 00 00 00  47 6c 6f 62 61 6c 56 61  |........GlobalVa|
00001028  72 00 47 43 43 3a 20 28  55 62 75 6e 74 75 20 35  |r.GCC: (Ubuntu 5|
```

As we can see, the content of the C variable "globalVariable" is written in
the ELF binary: "GlobalVar".



## Questions

* In which section and segment is the variable `globalStaticVariable` stored?
* In which section and segment is the variable `heapVar` stored?
* In which section and segment is the variable `localStackVar` stored?
* Can you locate the content of the variables in the ELF binary? If not, why not?
