# Azeria Labs: Process Memory and Memory Corruptions

This is based on: https://azeria-labs.com/process-memory-and-memory-corruption/.
This is the 32 bit Version.

Working directory is `~/challenges/challenge44/`.

## Stack Overflow

stack.c:
```
#include "stdio.h"

int main(int argc, char **argv)
{
  char buffer[8];
  gets(buffer);
}
```

Lets have a look at the main function in ARM assembly:
```
root@hlUbuntu32:~/challenges/challenge44# gdb -q stack
Reading symbols from stack...(no debugging symbols found)...done.
(gdb) disas main
Dump of assembler code for function main:
   0x000103f4 <+0>:     push    {r7, lr}
   0x000103f6 <+2>:     sub     sp, #16
   0x000103f8 <+4>:     add     r7, sp, #0
   0x000103fa <+6>:     str     r0, [r7, #4]
   0x000103fc <+8>:     str     r1, [r7, #0]
   0x000103fe <+10>:    add.w   r3, r7, #8
   0x00010402 <+14>:    mov     r0, r3
   0x00010404 <+16>:    blx     0x102e4 <gets@plt>
   0x00010408 <+20>:    movs    r3, #0
   0x0001040a <+22>:    mov     r0, r3
   0x0001040c <+24>:    adds    r7, #16
   0x0001040e <+26>:    mov     sp, r7
   0x00010410 <+28>:    pop     {r7, pc}
End of assembler dump.
```

Lets make a breakpoint after the `gets()`:
```
(gdb) b *0x00010408
Breakpoint 1 at 0x10408
```

And start the program, and insert seven 'A' on standard input:
```
(gdb) r
Starting program: /root/challenges/challenge44/stack
AAAAAAA
Breakpoint 1, 0x00010408 in main ()
```

And examine the stack:
```
(gdb) i r r0
r0             0xfffef5d0       4294899152
(gdb) x/32x $r0
0xfffef5d0:     0x41414141      0x00414141      0x00000000      0xf76f28ab
0xfffef5e0:     0xf77c4000      0xfffef734      0x00000001      0x000103f5
0xfffef5f0:     0xf77f0000      0xaaaaaaab      0x8aa92377      0x8238feea
0xfffef600:     0x0000012c      0x00000000      0x00010415      0x00000000
0xfffef610:     0x00000000      0x00000000      0xf77f0000      0x00000000
0xfffef620:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef630:     0x00000000      0x00000000      0x00000000      0x00000000
0xfffef640:     0x00000000      0x00000000      0x00000000      0x00000000
```


## Heap: Intra-chunk Heap overflow

intra_chunk.c:
```
#include "stdlib.h"
#include "stdio.h"

struct u_data                                          //object model: 8 bytes for name, 4 bytes for number
{
 char name[8];
 int number;
};

int main ( int argc, char* argv[] )
{
 struct u_data* objA = malloc(sizeof(struct u_data)); //create object in Heap

 objA->number = 1234;                                 //set the number of our object to a static value
 gets(objA->name);                                    //set name of our object according to user's input

 if(objA->number == 1234)                             //check if static value is intact
 {
  puts("Memory valid");
 }
 else                                                 //proceed here in case the static value gets corrupted
 {
  puts("Memory corrupted");
 }
}
```

## Heap: Inter-chunk Heap Overflow

inter_chunk.c:
```
#include "stdlib.h"
#include "stdio.h"

int main ( int argc, char* argv[] )
{
 char *some_string = malloc(8);  //create some_string "object" in Heap
 int *some_number = malloc(4);   //create some_number "object" in Heap

 *some_number = 1234;            //assign some_number a static value
 gets(some_string);              //ask user for input for some_string

 if(*some_number == 1234)        //check if static value (of some_number) is in tact
 {
 puts("Memory valid");
 }
 else                            //proceed here in case the static some_number gets corrupted
 {
 puts("Memory corrupted");
 }
}
```
