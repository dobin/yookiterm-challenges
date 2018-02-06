# Linux Hardening Analysis

This challenge checks some common Linux memory-corruption hardening
features. 

## ASLR

Check if ASLR is enabled. `2` is yes.

```
root@hlUbuntu64:~# cat /proc/sys/kernel/randomize_va_space
2
```

## Checksec

We'll make heavy use of the tool "checksec", available from:
* https://github.com/slimm609/checksec.sh

Different things can be checked:
* Files
* Processes
* Libraries used by processes

File:
```
root@hlUbuntu64:~/challenges/challenge60/checksec.sh --file /bin/bash
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FORTIFY Fortified Fortifiable  FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   Yes     13              33      /bin/bash
```

Processes:
```
root@hlUbuntu64:~/challenges/challenge60/checksec.sh --proc-all
* Does the CPU support NX: Yes

         COMMAND    PID RELRO           STACK CANARY            SECCOMP          NX/PaX        PIE                     FORTIFY
         systemd      1 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            cron    107 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        rsyslogd    124 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        dhclient    191 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            sshd    216 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
          agetty    219 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
            sshd    232 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            bash    243 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
 systemd-journal     39 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
   systemd-udevd     40 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes

```

Libraries used by `systemd`:
```
root@hlUbuntu64:~/challenges/challenge60/checksec.sh --proc-libs 1
* Does the CPU support NX: Yes

* Process information:

         COMMAND    PID RELRO           STACK CANARY            SECCOMP          NX/PaX        PIE                     Fortify Source
         systemd      1 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes


    RELRO               STACK CANARY   NX/PaX        PIE            RPath       RunPath   Fortify Fortified   Fortifiable

* Loaded libraries (file information, # of mapped files: 17):

  /lib/systemd/systemd:
    Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   Yes 14              32

  /lib/x86_64-linux-gnu/ld-2.23.so:
    Partial RELRO   No canary found   NX enabled    DSO             No RPATH   No RUNPATH   No  0               0

  /lib/x86_64-linux-gnu/libapparmor.so.1.4.0:
    Full RELRO      Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 8               13

  /lib/x86_64-linux-gnu/libaudit.so.1.0.0:
    Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 10              21

  /lib/x86_64-linux-gnu/libblkid.so.1.1.0:
    Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 8               22

  /lib/x86_64-linux-gnu/libc-2.23.so:
    Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 78              167

  /lib/x86_64-linux-gnu/libcap.so.2.24:
    Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 2               4

  /lib/x86_64-linux-gnu/libdl-2.23.so:
    Partial RELRO   No canary found   NX enabled    DSO             No RPATH   No RUNPATH   No  0               2

  /lib/x86_64-linux-gnu/libkmod.so.2.3.0:
    Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 7               13

  /lib/x86_64-linux-gnu/libmount.so.1.1.0:
    Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 8               24

  /lib/x86_64-linux-gnu/libpam.so.0.83.1:
    Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 5               12

  /lib/x86_64-linux-gnu/libpcre.so.3.13.2:
    Full RELRO      Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 1               4

  /lib/x86_64-linux-gnu/libpthread-2.23.so:
    Partial RELRO   No canary found   NX enabled    DSO             No RPATH   No RUNPATH   No  0               27

  /lib/x86_64-linux-gnu/librt-2.23.so:
    Partial RELRO   No canary found   NX enabled    DSO             No RPATH   No RUNPATH   No  0               3

  /lib/x86_64-linux-gnu/libseccomp.so.2.2.3:
    Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 1               2

  /lib/x86_64-linux-gnu/libselinux.so.1:
    Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 7               20

  /lib/x86_64-linux-gnu/libuuid.so.1.3.0:
    Partial RELRO   Canary found      NX enabled    DSO             No RPATH   No RUNPATH   Yes 2               4

```



## Stack Canary

Are the processes compiled with stack canary support?

```
root@hlUbuntu64:~/challenges/challenge60/checksec.sh --proc-all

* Does the CPU support NX: Yes

         COMMAND    PID RELRO           STACK CANARY            SECCOMP          NX/PaX        PIE                     FORTIFY
         systemd      1 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            cron    107 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        rsyslogd    124 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        dhclient    191 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            sshd    216 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
          agetty    219 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
            sshd    232 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            bash    243 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
 systemd-journal     39 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
   systemd-udevd     40 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
```

The row `STACK CANARY` shows if the process has stack canary support.


## DEP

Are the processes compiled with DEP support?

```
root@hlUbuntu64:~/challenges/challenge60/checksec.sh --proc-all

* Does the CPU support NX: Yes

         COMMAND    PID RELRO           STACK CANARY            SECCOMP          NX/PaX        PIE                     FORTIFY
         systemd      1 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            cron    107 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        rsyslogd    124 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        dhclient    191 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            sshd    216 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
          agetty    219 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
            sshd    232 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            bash    243 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
 systemd-journal     39 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
   systemd-udevd     40 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
```

The row `NX/PaX` shows if the process has DEP support.

## PIE

Are the processes compiled with PIE support?

```
root@hlUbuntu64:~/challenges/challenge60/checksec.sh --proc-all

* Does the CPU support NX: Yes

         COMMAND    PID RELRO           STACK CANARY            SECCOMP          NX/PaX        PIE                     FORTIFY
         systemd      1 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            cron    107 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        rsyslogd    124 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        dhclient    191 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            sshd    216 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
          agetty    219 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
            sshd    232 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            bash    243 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
 systemd-journal     39 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
   systemd-udevd     40 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
```

The row `NX/PaX` shows if the process has PIE support.

## Fortify Source

Are the processes compiled with Fortify Source support?

```
root@hlUbuntu64:~/challenges/challenge60/checksec.sh --proc-all

* Does the CPU support NX: Yes

         COMMAND    PID RELRO           STACK CANARY            SECCOMP          NX/PaX        PIE                     FORTIFY
         systemd      1 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            cron    107 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        rsyslogd    124 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        dhclient    191 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            sshd    216 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
          agetty    219 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
            sshd    232 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            bash    243 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
 systemd-journal     39 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
   systemd-udevd     40 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
```

The row `FORTIFY` shows if the process has Fortify Source support.

## GOT Protection: RELRO

Is "read-only relocations" active?

```
root@hlUbuntu64:~/challenges/challenge60/checksec.sh --proc-all

* Does the CPU support NX: Yes

         COMMAND    PID RELRO           STACK CANARY            SECCOMP          NX/PaX        PIE                     FORTIFY
         systemd      1 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            cron    107 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        rsyslogd    124 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
        dhclient    191 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            sshd    216 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
          agetty    219 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
            sshd    232 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
            bash    243 Partial RELRO   Canary found            Seccomp-bpf      NX enabled    No PIE                  Yes
 systemd-journal     39 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
   systemd-udevd     40 Full RELRO      Canary found            Seccomp-bpf      NX enabled    PIE enabled             Yes
```

The row `RELRO` row gives information about RELRO.


# Questions

## Distribution Hardening

Choose your favorite Linux distribution. Check the security level.

Is it better or worse than the tested Ubuntu 16.04 above?

## Software Hardening

Check the security flags of your favorite Linux software, which is not installed
by default. For example Firefox, or Eclipse.

## Additional Hardening

Is there something missing above? Are all hardening implementations, which are
mentioned in https://wiki.ubuntu.com/Security/Features, checkable? Which one's
not, and why not? (Note: Focus on Anti-Memory Corruption Mitigation Featuers).

# Answers

## Additional Hardening

e.g.:
* Heap Protector
* LIBS/MMAP ASLR
* EXEC ASLR
* BRK ASLR
* VDSO ASLR
* BIND_NOW
* Control Flow Integrity (CFI)

# References

* https://wiki.ubuntu.com/Security/Features
* https://blog.quarkslab.com/clang-hardening-cheat-sheet.html
