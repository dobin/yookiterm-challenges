# C buffer analysis - simple

## Introduction

We will talk about C buffers and other structures here.


## Goal

- Learn more about C and its data structures
- Learn how data structres are implemented in memory
- Learn a bit about C pointers


## Source

Source directory: `~/challenges/challenge02/`

The relevant file `datastructures.c`:
```
...
void funcWithArray() {
        unsigned int dummy1 = 0xaabbccdd;
        char charArray[4];
        unsigned int dummy2 = 0x11223344;

        printf("funcWithArray:\n");

        charArray[0] = 1;
        charArray[1] = 2;
        charArray[2] = 3;
        charArray[3] = 4;

        printf("Dummy 1 (%p): %i/0x%x\n", &dummy1, dummy1, dummy1);
        printf("Dummy 2 (%p): %i/0x%x\n\n", &dummy2, dummy2, dummy2);

        printf("CharArray #0  (%p): %i/0x%hhx\n", (void *) &charArray[0], charArray[0], charArray[0]);
        printf("CharArray #1  (%p): %i/0x%hhx\n", (void *) &charArray[1], charArray[1], charArray[1]);
        printf("CharArray #4  (%p): %i/0x%hhx\n", (void *) &charArray[4], charArray[4], charArray[4]);
        printf("CharArray #-1 (%p): %i/0x%hhx\n", (void *) &charArray[-1], charArray[-1], charArray[-1]);
}


struct cStruct {
        short x;
        long y;
        char z[3];
};

void funcWithStruct() {
        printf("funcWithStruct:\n");

        struct cStruct cstruct;
        cstruct.x = 1;
        cstruct.y = 2;
        cstruct.z[0] = 0x10;
        cstruct.z[1] = 0x11;
        cstruct.z[2] = 0x12;

        printf("cStruct.x    (%p): %i/0x%x)\n", (void *) &cstruct.x, cstruct.x, cstruct.x);
        printf("cStruct.y    (%p): %ld/0x%lx)\n", (void *) &cstruct.y, cstruct.y, cstruct.y);
        printf("cStruct.z[0] (%p): %i/0x%hhx)\n", (void *) &cstruct.z[0], cstruct.z[0], cstruct.z[0]);
        printf("cStruct.z[1] (%p): %i/0x%hhx)\n", (void *) &cstruct.z[1], cstruct.z[1], cstruct.z[1]);
        printf("cStruct.z[2] (%p): %i/0x%hhx)\n", (void *) &cstruct.z[1], cstruct.z[2], cstruct.z[2]);
}
...
```

You can compile it by calling `make` in the folder `~/challenges/challenge02`.

## Example Output

Check the output of the program. It prints the addresses of the variables
(usually in `()`, starting with 0xff), and its content. Does it make sense?

```
root@hlUbuntu32:~/challenges/challenge02# ./datastructures
funcWithArray:
Dummy 1 (0xffe3a2fc): -1430532899/0xaabbccdd
Dummy 2 (0xffe3a2f4): 287454020/0x11223344

CharArray #0  (0xffe3a2f8): 1/0x1
CharArray #1  (0xffe3a2f9): 2/0x2
CharArray #4  (0xffe3a2fc): -35/0xdd
CharArray #-1 (0xffe3a2f7): 17/0x11

funcWithStruct:
cStruct.x    (0xffe3a2f4): 1/0x1)
cStruct.y    (0xffe3a2f8): 2/0x2)
cStruct.z[0] (0xffe3a2fc): 16/0x10)
cStruct.z[1] (0xffe3a2fd): 17/0x11)
cStruct.z[2] (0xffe3a2fd): 18/0x12)

funcWithStrcpy:
Init:
0xffe3a2f8 Dest1 : 1111111
0xffe3a2f0 Dest2 : 2222222
After strncpy():
0xffe3a2f8 Dest1 : 1111111
0xffe3a2f0 Dest2 : 333333331111111
```

## Disassembly

Lets have a look at the disassembly of `funcWithArray`. You see a lot of
the hex magic values in the source code. Can you make sense of what
the individual statements do?

```
root@hlUbuntu32:~/challenges/challenge02# gdb -q ./datastructures
Reading symbols from ./datastructures...(no debugging symbols found)...done.
gdb-peda$ disas funcWithArray
Dump of assembler code for function funcWithArray:
   0x0804846b <+0>:     push   ebp
   0x0804846c <+1>:     mov    ebp,esp
   0x0804846e <+3>:     sub    esp,0x18
   0x08048471 <+6>:     mov    DWORD PTR [ebp-0xc],0xaabbccdd
   0x08048478 <+13>:    mov    DWORD PTR [ebp-0x14],0x11223344
   0x0804847f <+20>:    sub    esp,0xc
   0x08048482 <+23>:    push   0x80487c0
   0x08048487 <+28>:    call   0x8048330 <puts@plt>
   0x0804848c <+33>:    add    esp,0x10
   0x0804848f <+36>:    mov    BYTE PTR [ebp-0x10],0x1
   0x08048493 <+40>:    mov    BYTE PTR [ebp-0xf],0x2
   0x08048497 <+44>:    mov    BYTE PTR [ebp-0xe],0x3
   0x0804849b <+48>:    mov    BYTE PTR [ebp-0xd],0x4
   0x0804849f <+52>:    mov    edx,DWORD PTR [ebp-0xc]
   0x080484a2 <+55>:    mov    eax,DWORD PTR [ebp-0xc]
   0x080484a5 <+58>:    push   edx
   0x080484a6 <+59>:    push   eax
   0x080484a7 <+60>:    lea    eax,[ebp-0xc]
   0x080484aa <+63>:    push   eax
   0x080484ab <+64>:    push   0x80487cf
   0x080484b0 <+69>:    call   0x8048320 <printf@plt>
   0x080484b5 <+74>:    add    esp,0x10
   0x080484b8 <+77>:    mov    edx,DWORD PTR [ebp-0x14]
   0x080484bb <+80>:    mov    eax,DWORD PTR [ebp-0x14]
   0x080484be <+83>:    push   edx
   0x080484bf <+84>:    push   eax
   0x080484c0 <+85>:    lea    eax,[ebp-0x14]
   0x080484c3 <+88>:    push   eax
   0x080484c4 <+89>:    push   0x80487e6
   0x080484c9 <+94>:    call   0x8048320 <printf@plt>
...
```

## Questions

0) Can you draw a picture of the variables of function `funcWithArray` ?

1) Do the addresses of the variables make sense? Do they correspond with the allocations in the code?

2) Why is charArray[4] = 0xdd?

3) Why is charArray[-1] = 0x11?

4) Why are the addresses of the variables inside the cStruct counting upwards, while the variables in `funcWithArray` they are counting down?

5) Can you locate the initialization of the arrays and structs in the disassembly (objdump/gdb)? How are they performed? Why?

## Answers

2) charArray[4] is further "up" the stack (towards higher memory addresses), in dummy1. The first byte of dummy1, and its little endian, therefore the last byte.

3) charArray[-1] is further "down" the stack (towards lower memory addresses), therefore we will access last byte of dummy2, and its little endian, therefore the first byte.

4) in `funcWithArray` they are allocated on the stack, while cStruct is just a normal data structure like an array, where the individual elements get allocated behind each other.

5) This requires know-how of the function call convention of C on x86. But, they initialized and referenced via EBP.
