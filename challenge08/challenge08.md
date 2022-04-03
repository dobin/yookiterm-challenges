# C buffer analysis - with debugging


## Introduction

We have a vulnerable program which allows us to perform out-of-bound reads.
By debugging and analyzing it we will look at internal stack data of the process by
supplying adequate program inputs.


## Goal

* Understand C arrays by misusing them
* Get comfortable with GDB
* Use a memory leak


## Source

File: `~/challenges/challenge08/challenge08.c`
```c
void main(int argc, char **argv) {
        if (argc != 2) {
                printf("Usage: %s <idx>\n", argv[0]);
                return;
        }

        int array[4] = { 0xAA, 0xBB, 0xCC, 0xDD };
        int idx = atoi(argv[1]);
        printf("Number at index %i: 0x%x\n", idx, array[idx]);
}

```

You can compile it by calling `make` in the folder `~/challenges/challenge08`. 

## Execution

The program allows us to view 32 bit values of the `array[4]` array, by supplying
the index as the first argument. The array is of length 4, so we can try showing 
the first and last element:

```sh
~/challenges/challenge08$ ./challenge08 0
Number at index 0: 0xaa
~/challenges/challenge08$ ./challenge08 3
Number at index 3: 0xdd
```

Works as intended. But what if we increase the index even more?

```
~/challenges/challenge08$ ./challenge08 4
Number at index 4: 0x4
~/challenges/challenge08$ ./challenge08 5
Number at index 5: 0xf7fe3230
~/challenges/challenge08$ ./challenge08 6
Number at index 6: 0xffffdd60
```

The values at index 5 and 6, which are out of bound of the 4-element long array,
with values `0xf7fe3230` and `0xffffdd60` look weird and random. Lets use GDB to analyze it. 


## Debugging

Lets debug the binary. Start gdb, and disas the `main` function:
```
(gdb) disas main
Dump of assembler code for function main:
   0x08049172 <+0>:     lea    0x4(%esp),%ecx
   0x08049176 <+4>:     and    $0xfffffff0,%esp
   0x08049179 <+7>:     push   -0x4(%ecx)
   0x0804917c <+10>:    push   %ebp
   0x0804917d <+11>:    mov    %esp,%ebp
   0x0804917f <+13>:    push   %ecx
   0x08049180 <+14>:    sub    $0x24,%esp
   0x08049183 <+17>:    mov    %ecx,%eax
   0x08049185 <+19>:    cmpl   $0x2,(%eax)
   0x08049188 <+22>:    je     0x80491a2 <main+48>
   0x0804918a <+24>:    mov    0x4(%eax),%eax
   0x0804918d <+27>:    mov    (%eax),%eax
   0x0804918f <+29>:    sub    $0x8,%esp
   0x08049192 <+32>:    push   %eax
   0x08049193 <+33>:    push   $0x804a008
   0x08049198 <+38>:    call   0x8049030 <printf@plt>
   0x0804919d <+43>:    add    $0x10,%esp
   0x080491a0 <+46>:    jmp    0x80491f0 <main+126>
   0x080491a2 <+48>:    movl   $0xaa,-0x1c(%ebp)
   0x080491a9 <+55>:    movl   $0xbb,-0x18(%ebp)
   0x080491b0 <+62>:    movl   $0xcc,-0x14(%ebp)
   0x080491b7 <+69>:    movl   $0xdd,-0x10(%ebp)
   0x080491be <+76>:    mov    0x4(%eax),%eax
   0x080491c1 <+79>:    add    $0x4,%eax
   0x080491c4 <+82>:    mov    (%eax),%eax
   0x080491c6 <+84>:    sub    $0xc,%esp
   0x080491c9 <+87>:    push   %eax
   0x080491ca <+88>:    call   0x8049050 <atoi@plt>
   0x080491cf <+93>:    add    $0x10,%esp
   0x080491d2 <+96>:    mov    %eax,-0xc(%ebp)
   0x080491d5 <+99>:    mov    -0xc(%ebp),%eax
   0x080491d8 <+102>:   mov    -0x1c(%ebp,%eax,4),%eax
   0x080491dc <+106>:   sub    $0x4,%esp
   0x080491df <+109>:   push   %eax
   0x080491e0 <+110>:   push   -0xc(%ebp)
   0x080491e3 <+113>:   push   $0x804a019
   0x080491e8 <+118>:   call   0x8049030 <printf@plt>
   0x080491ed <+123>:   add    $0x10,%esp
   0x080491f0 <+126>:   mov    -0x4(%ebp),%ecx
   0x080491f3 <+129>:   leave
   0x080491f4 <+130>:   lea    -0x4(%ecx),%esp
   0x080491f7 <+133>:   ret
End of assembler dump.
```

We want to break before the 2nd `printf` is called, therefore at address `0x080491e8 <main+118>:`, and
run the program (the index parameter is not really relevant):

```
(gdb) b *main+118
Breakpoint 1 at 0x80491e8
(gdb) r 0
Starting program: /root/challenges/challenge08/challenge08 0

Breakpoint 1, 0x080491e8 in main ()
(gdb)
```

We stopped execution before the printf() executed. Lets examine the stack.
We use the command `x/32x $esp`. The command is called `x`, for `eXamine`. The
`/32x $esp` means we want to print 32 hex values (of default size), starting from
the address stored in register `esp`:
```
(gdb) x/32x $esp
0xffffdcc0:     0x0804a019      0x00000000      0x000000aa      0xf7e13c1e
0xffffdcd0:     0xf7fc13fc      0xffffffff      0x00000000      0x000000aa
0xffffdce0:     0x000000bb      0x000000cc      0x000000dd      0x00000000
0xffffdcf0:   ->0xf7fe3230<-    0xffffdd10      0x00000000      0xf7dfae46
0xffffdd00:     0xf7fc1000      0xf7fc1000      0x00000000      0xf7dfae46
0xffffdd10:     0x00000002      0xffffddb4      0xffffddc0      0xffffdd44
0xffffdd20:     0xffffdd54      0xf7ffdb40      0xf7fca410      0xf7fc1000
0xffffdd30:     0x00000001      0x00000000      0xffffdd98      0x00000000
```

Seems like the value `0xf7fe3230` is located on the stack, right after the array
(fourth line, first entry, at address 0xffffdcf0). Above it are the other values of the array;
0xAA, 0xBB, 0xCC, 0xDD. 

Note that while the stack grows down, buffers
or arrays on the stack still grow upwards (towards higher addresses).
Printing values from memory will also print from increasing memory addresses, but
higher addresses will come later, and therefore futher down in the text output.


## Things to think about

* Give the above stack dump, what value would be displayed when calling `challenge08 8`?
  * Note: If you want to test your assumption, make sure to execute the binary in gdb. GDB- and non-GDB execution have a small difference in the stack layout.
* What is the base/starting address of the array `array`? Is it the same as the first array element?
