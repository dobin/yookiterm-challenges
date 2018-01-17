# Introduction to C buffers

## Introduction

We will talk about C buffers and other structures here.


## Goal

- Learn more about C and its data structures
- Learn how data structres are implemented in memory
- Learn a bit about C pointers


## Source

Source directory: `~/challenges/challenge02/`

The relevant file `datastructures.c`:
```c
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



## Questions

0) Can you draw a picture of the variables of function `funcWithArray` ?

1) Do the addresses of the variables make sense? Do they correspond with the allocations in the code?

2) Why is charArray[4] = 0xdd?

3) Why is charArray[-1] = 0x11?

4) Why are the addresses of the variables inside the cStruct counting upwards, while the variables in `funcWithArray` they are counting down?



## Answers

2) charArray[4] is further "up" the stack (towards higher memory addresses), in dummy1. The first byte of dummy1, and its little endian, therefore the last byte.

3) charArray[-1] is further "down" the stack (towards lower memory addresses), therefore we will access last byte of dummy2, and its little endian, therefore the first byte.

4) in `funcWithArray` they are allocated on the stack, while cStruct is just a normal data structure like an array, where the individual elements get allocated behind each other.
