# Fuzzing

## Introduction

## Source

Source directory: `~/challenges/challenge53/`

Relevant files:
* challenge53.c
* test.dob (input file for challenge53)

You can compile it by typing `make`. It will generate:

* challenge53: Compiled with GDB, production build
* challenge53-fuzz: Compiled with AFL-Clang
* challenge53-asan: Compiled Clang


## Behaviour

Input file:
```
~/challenges/challenge53$ hexdump -C test.dob
00000000  54 45 53 54 20 00 02 00  01 00 00 00 04 00 00 00  |TEST ...........|
00000010  04 00 00 00 42 42 42 42  02 00 00 00 02 00 00 00  |....BBBB........|
00000020  04 00 00 00 43 43 43 43                           |....CCCC|
```

Executing the binary with the input file:
```
~/challenges/challenge53$ ./challenge53 test.dob
FileImage: 0
  idx : 0
  size: 4
  data: BBB
FileImage: 1
  idx : 1
  size: 4
  data: CCC
```


## Fuzzing

Create `input/` and `output/` directories. Copy example input file `test.dob` into `input/`:
```
~/challenges/challenge53$ mkdir input output
~/challenges/challenge53$ cp test.dob input/
```

Start afl-fuzz:
```
~/challenges/challenge53$ afl-fuzz -i input -o output -- ./challenge53-fuzz @@

       american fuzzy lop ++4.01a {default} (./challenge53-fuzz) [fast]
┌─ process timing ────────────────────────────────────┬─ overall results ────┐
│        run time : 0 days, 0 hrs, 0 min, 1 sec       │  cycles done : 0     │
│   last new find : 0 days, 0 hrs, 0 min, 0 sec       │ corpus count : 6     │
│last saved crash : 0 days, 0 hrs, 0 min, 0 sec       │saved crashes : 6     │
│ last saved hang : none seen yet                     │  saved hangs : 0     │
├─ cycle progress ─────────────────────┬─ map coverage┴──────────────────────┤
│  now processing : 0.0 (0.0%)         │    map density : 0.00% / 0.00%      │
│  runs timed out : 0 (0.00%)          │ count coverage : 1.37 bits/tuple    │
├─ stage progress ─────────────────────┼─ findings in depth ─────────────────┤
│  now trying : havoc                  │ favored items : 1 (16.67%)          │
│ stage execs : 400/8192 (4.88%)       │  new edges on : 5 (83.33%)          │
│ total execs : 461                    │ total crashes : 130 (6 saved)       │
│  exec speed : 282.5/sec              │  total tmouts : 12 (3 saved)        │
├─ fuzzing strategy yields ────────────┴─────────────┬─ item geometry ───────┤
│   bit flips : disabled (default, enable with -D)   │    levels : 2         │
│  byte flips : disabled (default, enable with -D)   │   pending : 6         │
│ arithmetics : disabled (default, enable with -D)   │  pend fav : 1         │
│  known ints : disabled (default, enable with -D)   │ own finds : 5         │
│  dictionary : n/a                                  │  imported : 0         │
│havoc/splice : 0/0, 0/0                             │ stability : 100.00%   │
│py/custom/rq : unused, unused, unused, unused       ├───────────────────────┘
│    trim/eff : 0.00%/9, disabled                    │          [cpu000:150%]
└────────────────────────────────────────────────────┘
```

You can stop it after a few seconds with ctrl-c. 


## Analysis

The mutated files which made the process crash are stored in `output/default/crashes/`:
```
~/challenges/challenge53$ ls -1 output/default/crashes/
README.txt
id:000000,sig:06,src:000000,time:88,execs:19,op:havoc,rep:8
id:000001,sig:11,src:000000,time:150,execs:39,op:havoc,rep:4
id:000002,sig:06,src:000000,time:161,execs:45,op:havoc,rep:2
id:000003,sig:06,src:000000,time:666,execs:136,op:havoc,rep:2
id:000004,sig:11,src:000000,time:674,execs:138,op:havoc,rep:16
id:000005,sig:06,src:000000,time:954,execs:236,op:havoc,rep:8
id:000006,sig:06,src:000000,time:2464,execs:734,op:havoc,rep:8
```

Try reproducing the crashes with the `challenge53-asan` binary. For example:
```
~/challenges/challenge53$ ./challenge53-asan output/default/crashes/id\:000000*
=================================================================
==2543==ERROR: AddressSanitizer: requested allocation size 0x1f203e410002 (0x1f203e411008 after adjustments for alignment, red zones etc.) exceeds maximum supported size of 0x10000000000 (thread T0)
    #0 0x49833d in malloc (/root/challenges/challenge53/challenge53-asan+0x49833d)
    #1 0x4c827c in parseFileHeader /root/challenges/challenge53/challenge53.c:76:23
    #2 0x4c8450 in main /root/challenges/challenge53/challenge53.c:97:28

==2543==HINT: if you don't care about these errors you may set allocator_may_return_null=1
SUMMARY: AddressSanitizer: allocation-size-too-big (/root/challenges/challenge53/challenge53-asan+0x49833d) in malloc
==2543==ABORTING
```

Do it again for all output files. Which ones is the easiest to exploit? 


## Write exploit

Once you found a suitable vulnerability, try planning or even writing your exploit.

Use the common `challenge53` binary, which does not have address sanitizer or fuzzing enabled. 

