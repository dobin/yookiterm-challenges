# Function Call Convention in x86 (32bit)

## Introduction

In this challenge, we'll analyze the call convention of a binary. This binary
contains different functions with different parameters.


## Goal

* See function call convention in action
* Get a feeling how function call convention looks like in assembly


## Source

* Source directory: `~/challenges/challenge06/`
* Source files: [challenge06](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge06)

You can compile it by calling `make` in the folder `~/challenges/challenge06`


## Analysis

### functionMinimal()

This is a minimalistic function with no arguments.

```c
void functionMinimal(void) {
        return;
}
```

When disassembled, We see the standard function prolog and epilogue.

```sh
(gdb) disas functionMinimal
Dump of assembler code for function functionMinimal:
   0x08049162 <+0>:     push   ebp
   0x08049163 <+1>:     mov    ebp,esp
   0x08049165 <+3>:     nop
   0x08049166 <+4>:     pop    ebp
   0x08049167 <+5>:     ret
End of assembler dump.
```

The only command of the function is `nop` (do nothing).


### functionInt(int c)

This function takes an integer as a parameter, copies it to a local stack
variable.

```c
void functionInt(int c) {
        int d;
        d = c + 1;
}
```

In assembly:

```sh
(gdb) disas functionInt
Dump of assembler code for function functionInt:
   0x08049168 <+0>:     push   ebp
   0x08049169 <+1>:     mov    ebp,esp
   0x0804916b <+3>:     sub    esp,0x10
   0x0804916e <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x08049171 <+9>:     add    eax,0x1
   0x08049174 <+12>:    mov    DWORD PTR [ebp-0x4],eax
   0x08049177 <+15>:    nop
   0x08049178 <+16>:    leave
   0x08049179 <+17>:    ret
End of assembler dump.
```

It is called like this in the parent function:
```sh
(gdb) disas main
Dump of assembler code for function main:
[...]
   0x080491b8 <+36>:    push   0x5
   0x080491ba <+38>:    call   0x8049168 <functionInt>
```

The argument of `functionBasic()`, 0x5, is stored on the stack. It is referenced
via `0x8(%ebp)`. 


### functionString(char *a, char *b)

The `functionAdvanced` takes two char pointer as arguments, and returns a char pointer:

```c
void functionString(char *a, char *b) {
        strcpy(a, b);
}
```

The disassembly:
```sh
(gdb) disas functionString
Dump of assembler code for function functionString:
   0x0804917a <+0>:     push   ebp
   0x0804917b <+1>:     mov    ebp,esp
   0x0804917d <+3>:     sub    esp,0x8
   0x08049180 <+6>:     sub    esp,0x8
   0x08049183 <+9>:     push   DWORD PTR [ebp+0xc]
   0x08049186 <+12>:    push   DWORD PTR [ebp+0x8]
   0x08049189 <+15>:    call   0x8049030 <strcpy@plt>
   0x0804918e <+20>:    add    esp,0x10
   0x08049191 <+23>:    nop
   0x08049192 <+24>:    leave
   0x08049193 <+25>:    ret
End of assembler dump.
```

It is called like this in the parent function `main()`:

```
(gdb) disas main
Dump of assembler code for function main:
   0x080491a5 <+17>:    mov    DWORD PTR [ebp-0xc],0x804a008
   0x080491ac <+24>:    mov    DWORD PTR [ebp-0x10],0x804a00e
[...]
   0x080491c5 <+49>:    push   DWORD PTR [ebp-0x10]
   0x080491c8 <+52>:    push   DWORD PTR [ebp-0xc]
   0x080491cb <+55>:    call   0x804917a <functionString>
   0x080491d0 <+60>:    add    esp,0x10
```

The arguments are pushed on the stack before the `call`. They get cleaned up
by calling `add esp, 0x10` which increments esp by 16 bytes. 


## Things to think about

### Primary

* If the first argument is at EBP+0x8, what is at EBP+0x4 and EBP+0x0? What is at EBP+0xc?
* Why are arguments referenced with a positive number via EBP (e.g. EBP+0x8), and local variables with a negative number (e.g. EBP-0x4) ?
* What is the assembly command "leave" doing?

### Secondary

* The code was compiled without any optimization (-O0). What happens if you enable optimization?
* The code was also compiled with `-fno-omit-frame-pointer`. What happens if you compile it without this parameter? Why could this be useful?

### Tertiary

* How is the return value of a function communicated to the parent function?
* Compile the code on an 64 bit machine. Analyse the call convention again.

