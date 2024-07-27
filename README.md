# HeapViewer

HeapViewer is small tool to visualize the heap using ptrace. 

The goal is to print all the heap chunks until my estimated top chunk is met.

You can either:
- attach to an existing process 
- launch a process 

HeapViewer allows you to print the heap state at :
- each instruction of the program (.text section)
- each SYSCALL 


> [!WARNING]  
> Printing the heap state at each instruction is VERY SLOW due to usage of PTRACE_SINGLESTEP. Do not use it on medium/large binary ! 


## Installation

```bash
make
```

## Usage

```bash
usage: ./heapView MODE TYPE BINARY_NAME 

MODE: NORMAL | ATTACH 
TYPE: SINGLE | SYSCALL


NORMAL:  [SINGLE|SYSCALL] BINARY_NAME

        ex: ./heapView NORMAL SSTEP PATH_TO_BINARY_NAME

        ex: ./heapView NORMAL SYSCALL PATH_TO_BINARY_NAME

ATTACH:  [SINGLE|SYSCALL] BINARY_NAME PID

        ex: ./heapView ATTACH SSTEP PATH_TO_BINARY_NAME PID

        ex: ./heapView ATTACH SYSCALL PATH_TO_BINARY_NAME PID


SSTEP (for single step) : print heap at each instruction inside .text of the binary
SYSCALL: print heap whenever a SYSCALL happen
```

> [!NOTE]  
> In some cases due to kernel hardening , PTRACE_ATTACH may required sudo privileges => echo 0 > /proc/sys/kernel/yama/ptrace_scope


## DEMO

NORMAL MODE with single step

![normal_sstep](gif/normal_sstep.gif)

NORMAL MODE with SYSCALL

![normal_syscall](gif/normal_syscall.gif)


ATTACH MODE with SYSCALL

![attach_syscall](gif/attach_syscall.gif)
