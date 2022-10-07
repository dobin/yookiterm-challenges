# Introduction to memory layout: C data structures

## Introduction

In this challenge we will analyze some data structures in a C program.
By looking at memory pointers, we will be able to deduce how C organizes
some variables in memory.


## Goal

* Learn a bit about C pointers
* Learn more about C data structures


## Source

Source directory: `~/challenges/challenge02/`

Source: [challenge2.c](https://github.com/dobin/yookiterm-challenges-files/blob/master/challenge02/challenge2.c)

You can compile it by calling `make` in the folder `~/challenges/challenge02`.


## Stack

Lets analyze some stack variables:
```
~/challenges/challenge02$ ./challenge02 array
unsigned int stackTop = 0xaabbccdd;
char charArray[4] = { 1, 2, 3, 4 };
unsigned int stackBot = 0x11223344;

stackBot      @ 0xffffdd04: 0x11223344
charArray[-1] @ 0xffffdd07: 0x11 (part of stackBot)
charArray[0]  @ 0xffffdd08: 0x1
charArray[1]  @ 0xffffdd09: 0x2
charArray[4]  @ 0xffffdd0c: 0xdd (part of stackTop)
stackTop      @ 0xffffdd0c: 0xaabbccdd
```

The `charArray[4]` is sandwiched between `stackTop` and `stackBottom`. 
We can access the `charArray` out-of-band, by using `charArray[-1]=0x11` and 
`charArray[4]=0xdd`, which will access the neighbouring variables. 

Does the result make any sense? Is the `top` in `stackTop` because of the memory address, or 
the usage of the stack?

Take a piece of paper and try to draw the variables in a stack frame. 


## Struct

A struct is just an array with different length of variables:
```
~/challenges/challenge02$ ./challenge02 struct
struct cStruct {
        short x;
        long y;
        char z[2];
};
cstruct.x = 1;
cstruct.y = 2;
cstruct.z[0] = 0x10;
cstruct.z[1] = 0x11;

cStruct.x    @ 0xffffdd08 (size 2)
cStruct.y    @ 0xffffdd0a (size 4)
cStruct.z[0] @ 0xffffdd0e (size 1)
cStruct.z[1] @ 0xffffdd0f (size 1)
```

The whole struct is just a continous piece of memory, indexed at different offsets. 


## Strings / Char Arrays

Strings in C are just byte arrays, ending with a null byte 0x00. 
That means that we have one byte / character less space than the buffer is sized for. 
So a 8 byte char buffer can hold a string of 7 bytes, and its terminating 0x00 byte. 

In the following example, we accidently overwrite the trailing 0x00 byte of a string:
```
~/challenges/challenge02$ ./challenge02 strncpy
char dest1[8] = "1234567\0";
char dest2[8] = "1234567\0";

dest1 @ 0xffffdcf8: 1234567
dest2 @ 0xffffdcf0: 1234567
After strncpy(dest2, "AABBCCDD"), without space for nul:
dest1 @ 0xffffdcf8: 1234567
dest2 @ 0xffffdcf0: AABBCCDD1234567 (missing nul terminator)
```

As we can see, after copying 8 bytes "AABBCCDD" into a 8 byte char array,
C thinks the string is actually "AABBCCDD123457", as it does not find the nul
terminator. 

Take a piece of paper, and draw the before/after `strncpy()` strings `dest1` and `dest2`. 

