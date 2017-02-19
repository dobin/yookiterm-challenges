# Function Call Convention in x86 (32bit)

## Introduction

In this challenge, we'll analyze the call convention of a binary. This binary
contains different functions with different parameters.

## Goal

* See function call convention in action
* Get a feeling how function call convention looks like in assembly


## source

File: `~/challenges/challenge07/challenge7.c`
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void functionMinimal(void) {
        return;
}

int functionBasic(int c) {
        int d;
        d = c + 1;
        return d;
}

char* functionAdvanced(char *a, char *b) {
        strcpy(a, b);
        return a;
}


int main(int argc, char **argv) {
        char *a = "AAAAA";
        char *b = "BBB";
        int ret2;
        char *ret3;

        functionMinimal();

        ret2 = functionBasic(5);

        ret3 = functionAdvanced(a, b);
}
```

You can compile it by calling `make` in the folder `~/challenges/challenge07`


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
gdb-peda$ disas functionMinimal
Dump of assembler code for function functionMinimal:
   0x0804840b <+0>:     push   ebp
   0x0804840c <+1>:     mov    ebp,esp
   0x0804840e <+3>:     nop
   0x0804840f <+4>:     pop    ebp
   0x08048410 <+5>:     ret
End of assembler dump.
```

The only command of the function is `nop` (do nothing).

### functionBasic()

This function takes an integer as a parameter, copies it to a local stack
variable, increments it and returns it.

```c
int functionBasic(int c) {
        int d;
        d = c + 1;
        return d;
}
```

In assembly:

```sh
gdb-peda$ disas functionBasic
Dump of assembler code for function functionBasic:
   0x08048411 <+0>:     push   ebp
   0x08048412 <+1>:     mov    ebp,esp
   0x08048414 <+3>:     sub    esp,0x10
   0x08048417 <+6>:     mov    eax,DWORD PTR [ebp+0x8]
   0x0804841a <+9>:     add    eax,0x1
   0x0804841d <+12>:    mov    DWORD PTR [ebp-0x4],eax
   0x08048420 <+15>:    mov    eax,DWORD PTR [ebp-0x4]
   0x08048423 <+18>:    leave
   0x08048424 <+19>:    ret
```

It is called like this:
```sh
gdb-peda$ disas main
Dump of assembler code for function main:
[...]
   0x08048465 <+36>:    push   0x5
   0x08048467 <+38>:    call   0x8048411 <functionBasic>
```

The argument of `functionBasic()`, 0x5, is stored on the stack. It is referenced
via `ebp+0x8`. The return value is stored in the register `eax`.


### functionAdvanced()

The `functionAdvanced` takes two char pointer as arguments, and returns a char pointer:

```c
char* functionAdvanced(char *a, char *b) {
        strcpy(a, b);
        return a;
}
```

The disassembly:
```sh
gdb-peda$ disas functionAdvanced
Dump of assembler code for function functionAdvanced:
   0x08048425 <+0>:     push   ebp
   0x08048426 <+1>:     mov    ebp,esp
   0x08048428 <+3>:     sub    esp,0x8
   0x0804842b <+6>:     sub    esp,0x8
   0x0804842e <+9>:     push   DWORD PTR [ebp+0xc]
   0x08048431 <+12>:    push   DWORD PTR [ebp+0x8]
   0x08048434 <+15>:    call   0x80482e0 <strcpy@plt>
   0x08048439 <+20>:    add    esp,0x10
   0x0804843c <+23>:    mov    eax,DWORD PTR [ebp+0x8]
   0x0804843f <+26>:    leave
   0x08048440 <+27>:    ret
```

It is called like this in `main()`:

```
0x08048475 <+52>:    push   DWORD PTR [ebp-0x14]                               
0x08048478 <+55>:    push   DWORD PTR [ebp-0x18]                               
0x0804847b <+58>:    call   0x8048425 <functionAdvanced>                       
0x08048480 <+63>:    add    esp,0x10                                           
0x08048483 <+66>:    mov    DWORD PTR [ebp-0xc],eax                            
```

The arguments are pushed on the stack before the `call`. They get cleaned up
by calling `add esp, 0x10` which increments esp by 16 bytes. The return value
of `functionAdvanced` is stored in `ebp-0xc`, which seems to be `ret3`.


## Questions

### Primary

* If the first argument is at EBP+0x8, what is at EBP+0x4 and EBP+0x0? What is at EBP+0xc?
* Why are arguments referenced with a positive number via EBP (e.g. EBP+0x8), and local variables with a negative number (e.g. EBP-0x4) ?
* What is the assembly command "leave" doing?

### Secondary

* The code was compiled without any optimization (-O0). What happens if you enable optimization?
* The code was also compiled with `-fno-omit-frame-pointer`. What happens if you compile it without this parameter? Why could this be useful?

### Tertiary

* Compile the code on an 64 bit machine. Analyse the call convention again.
