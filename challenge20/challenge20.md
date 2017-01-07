# ARM 32 Bit Intro

## Example program

# cat test.c                             
```sh
#include <stdio.h>                                                

void test(int n) {                                                
        printf("NN: %i\n", n);                                    
}                                                                 

void main(void) {                                                 
        int n=42;                                                 
        printf("n: %i\n", n);                                     
        test(n);                                                  
}                                   
```

Analysis:

```c
gdb) disas main                                                  
Dump of assembler code for function main:                         
   0x00010418 <+0>:     push    {r7, lr}                          
   0x0001041a <+2>:     sub     sp, #8                            
   0x0001041c <+4>:     add     r7, sp, #0                        
   0x0001041e <+6>:     movs    r3, #42 ; 0x2a                    
   0x00010420 <+8>:     str     r3, [r7, #4]                      
   0x00010422 <+10>:    ldr     r1, [r7, #4]                      
   0x00010424 <+12>:    movw    r0, #1172       ; 0x494           
   0x00010428 <+16>:    movt    r0, #1                            
   0x0001042c <+20>:    blx     0x102e8 <printf@plt>              
   0x00010430 <+24>:    ldr     r0, [r7, #4]                      
   0x00010432 <+26>:    bl      0x103f8 <test>                    
   0x00010436 <+30>:    nop                                       
   0x00010438 <+32>:    adds    r7, #8                            
   0x0001043a <+34>:    mov     sp, r7                            
   0x0001043c <+36>:    pop     {r7, pc}                          
End of assembler dump.                                            
(gdb) disas 0x102e8                                               
Dump of assembler code for function printf@plt:                   
   0x000102e8 <+0>:     add     r12, pc, #0, 12                   
   0x000102ec <+4>:     add     r12, r12, #16, 20       ; 0x10000
   0x000102f0 <+8>:     ldr     pc, [r12, #3356]!       ; 0xd1c   
End of assembler dump.                                         
```

```
gdb) disas main                                                  
Dump of assembler code for function main:                         
   0x00010418 <+0>:     push    {r7, lr}                          
   0x0001041a <+2>:     sub     sp, #8                      # sp -= 8 (make some space on stack)     
   0x0001041c <+4>:     add     r7, sp, #0                  # r7 = sp      
   0x0001041e <+6>:     movs    r3, #42 ; 0x2a              # r3 = 42      
   0x00010420 <+8>:     str     r3, [r7, #4]                # [r7 + 4] = r3   -> [sp + 4] = 42      
   0x00010422 <+10>:    ldr     r1, [r7, #4]                # r1 = [r7 + 4]   -> r1 = [sp + 4] = 42       
   0x00010424 <+12>:    movw    r0, #1172       ; 0x494     # r0 = 1172      
   0x00010428 <+16>:    movt    r0, #1                      # r0 = 66708 ??      
   0x0001042c <+20>:    blx     0x102e8 <printf@plt>        # r0 = first arg, addr of string "n: %i"      
   0x00010430 <+24>:    ldr     r0, [r7, #4]                # r0 = [r7 + 4] = 42, again      
   0x00010432 <+26>:    bl      0x103f8 <test>              # r0 = first arg, number 42      
   0x00010436 <+30>:    nop                                       
   0x00010438 <+32>:    adds    r7, #8                            
   0x0001043a <+34>:    mov     sp, r7                            
   0x0001043c <+36>:    pop     {r7, pc}                          
End of assembler dump.                                            
(gdb) disas 0x102e8                                               
Dump of assembler code for function printf@plt:                   
   0x000102e8 <+0>:     add     r12, pc, #0, 12                   
   0x000102ec <+4>:     add     r12, r12, #16, 20       ; 0x10000
   0x000102f0 <+8>:     ldr     pc, [r12, #3356]!       ; 0xd1c   
End of assembler dump.                                         
```

# Arm basics

## Registers

```
r0 - r10    General Purpose
sp          Stack pointer
ip          Intra-procedure register
fp          Frame pointer
pc          Program counter
```

IP is just a temporary register, which subroutines can freely use. The rest (SP, IP, FP) is the same as in x86.

## Math operations

```
add r1, r2, #4     # r1 = r2 + 4
add r1, r2, r3     # r1 = r2 + r3
rsb r5, r5, #10    # r5 = ???
```

## Load and store

```
ldr r0, [r1, #4]   # r0 = [r1 + 4]
str r0, [r1, #4]   # [r1 + 4] = r0
```

## Jumps

```
b 0x1234       Jump to 0x1234
bl 0x1234      Jump to 0x1234, and set r14 = next addr (return address)
```
