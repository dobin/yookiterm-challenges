# GDB Tutorial


## Disassemble

Disassemble a library or function, by name:

```
disas main
```

Disassemble based on a memory address:
```
disas 0xbefffd74
```


## Breakpoints

Setting a breakpoint:
```
b main
b *0xabcd
```

Start:
```
run argument1 argument2
```

After hitting a breakpoint, it is possible to:

Continue execution:
```
c
```

Or, execute the next instruction
```
ni
```

## Inspect

Inspect a register:
```
info register eax
info register r1

x/x $eax
x/x $r
```

Inspect memory addresses:
```
x/x *0xbedfffaa
x/x *eax
x/x *r1
```

Inspect all registers:
```
info registers
```
