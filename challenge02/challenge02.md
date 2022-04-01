# Introduction to C data structures

## Introduction

We will talk about C buffers and other structures here.


## Goal

- Learn more about C and its data structures
- Learn how data structres are implemented in memory
- Learn a bit about C pointers


## Source

Source directory: `~/challenges/challenge02/`

Source: [challenge2.c](https://github.com/dobin/yookiterm-challenges-files/blob/master/challenge02/challenge2.c)

You can compile it by calling `make` in the folder `~/challenges/challenge02`.

## Stack

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


## Questions

0) Can you draw a picture of the variables of function `funcWithArray` ?

1) Do the addresses of the variables make sense? Do they correspond with the allocations in the code?

2) Why is charArray[4] = 0xdd?

3) Why is charArray[-1] = 0x11?

4) Why are the addresses of the variables inside the cStruct counting upwards, while the variables in `funcWithArray` they are counting down?


## Answers

2) charArray[4] is further "up" the stack (towards higher memory addresses), therefore adjectant to `stackTop` (which got initialized first).

3) charArray[-1] is further "down" the stack (towards lower memory addresses), therefore we will access `stackBot` (which got initialized last).

4) in `funcWithArray` they are allocated on the stack which grows downward, while cStruct is just a normal data structure like an array, where the individual elements get allocated behind each other.
