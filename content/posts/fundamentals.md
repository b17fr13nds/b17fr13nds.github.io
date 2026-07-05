+++ 
draft = false
date = 2022-03-01T12:35:03+02:00
title = "Software and hardware fundamentals"
description = "Notes about basic computer knowledge"
slug = ""
authors = ["bitfriends"]
tags = ["architecture","linux","windows","glibc"]
categories = ["notes"]
externalLink = ""
series = []
+++

_Note that this is only an early reference that I initially created for mysELF. I decided to publish it for those, who want to have an overview of the fundamentals. If you spot any mistakes or if you think something should be added, please reach me on Discord (`bitfriends`). I used some pictures from other people because this was only a reference for me. The people who created the pictures are amazing and should feel honored :)_

## Table of contents
* Computer components are their functionalities \
&nbsp;– the CPU \
&nbsp;– the MMU \
&nbsp;– the RAM \
&nbsp;– the bus
* The x86(-64) architecture \
&nbsp;– overview \
&nbsp;– data \
&nbsp;– segmentation \
&nbsp;– CPU registers \
&nbsp;– call stack \
&nbsp;– privilege/protection rings
* Linux operating system and kernel \
&nbsp;– overview \
&nbsp;– the kernel \
&nbsp;– syscalls and interrupts \
&nbsp;– modern exploit mitigations (kernel space) \
&nbsp;– Linux calling convention 
* ELF file format (Linux) \
&nbsp;– overview \
&nbsp;– structure \
&nbsp;– how an ELF file is executed \
&nbsp;– static vs dynamic binaries \
&nbsp;– shared libraries \
&nbsp;– modern exploit mitigations (userspace) \
&nbsp;– the linker, the plt and the got
* Windows operating system and kernel \
&nbsp;– overview \
&nbsp;– the kernel \
&nbsp;– syscalls and interrupts \
&nbsp;– modern exploit mitigations (kernel space)\
&nbsp;– Windows calling convention
* PE file format (Windows) \
&nbsp;– overview \
&nbsp;– structure \
&nbsp;– modern exploit mitigations (userspace)
* Sources

## Computer components
### CPU (central processing unit - assuming it has x86 architecture)
It is a little electronic device that executes instructions (machine code). The CPU can do logic, arithmetic, controlling and input/output operations which are specified by the machine code instructions. The CPU is divided into units, each of them associated with specific tasks. The machine code is located in the main memory (RAM) and secondary memory. The CPU also has registers that are like global variables. They are locations in the CPU that can be used to store small amounts of data. The size of the registers depends on the processor architecture and generation. The CPU cache is used by the CPU to save resources. It is closer to the CPU than the main memory and it stores copied data which is more frequently used. Most CPUs have a hierarchy of multiple cache levels, in most cases L1, L2, and L3. While every CPU core has its own L1 and L2 cache, the L3 cache is always shared between them. CPU cache is utilized for frequently-used data, to allow faster access.

![CPU](http://computerscience.gcse.guru/wp-content/uploads/2016/04/Von-Neumann-Architecture-Diagram.jpg)

### RAM (random access memory) & virtual memory
The RAM is our main memory. It is a device where machine code and other data are stored. If we have a process, its code and most other data are in memory. If we have multiple programs running, using physical memory alone would be inefficient and expensive. Also, you don't want your program to interact with the hardware directly. Instead, it should think, that it has access to all available memory. Mainly because of that reason, every process has its own memory (called virtual memory), while the process can't access the virtual memory of another process. Virtual memory is partially in the physical address space and some fragments are in inactive/secondary memory, which form a range of continuous addresses. Address spaces that are more frequently used get more main memory than those that aren't read or written that often. The operating system tries to effectively move less frequently used data into secondary memory, which is known as swapping. Also, big parts of the kernel are mapped to each program's virtual address space (not directly accessible). There is also data in the kernel which is process-specific. This data is not shared between processes, instead, each has its unique data.

### MMU
The MMU is part of the CPU (CPU unit) and it's a computer hardware unit having all memory references passed through itsELF, primarily performing the translation of virtual memory addresses to physical addresses. Modern MMUs typically divide the virtual address space into pages (chunks of memory, typically 1KB). Most MMUs use an in-memory table of items called a page table (which is stored in kernel space of a program's virtual address space), containing one page table entry per page, to map virtual page numbers to physical page numbers in main memory. The MMU knows where the current page table of the process is because the address of it is stored in a CPU register. Simply said, the MMU is responsible to translate virtual addresses to physical addresses. They also have a cache called translation lookaside buffer.

![MMU](https://upload.wikimedia.org/wikipedia/commons/thumb/d/dc/MMU_principle_updated.png/325px-MMU_principle_updated.png)

### BUS
A bus is a communication system that transfers data between components inside a computer. An address bus is a bus that is used to specify a physical address. When a processor needs to read or write to a memory location, it specifies that memory location on the address bus with a physical address (data is sent on the data bus). Just imagine the data bus like a highway that transfers data. The location of what to read or write is specified on the address bus.

## The x86 architecture
### Overview
Different CPUs may have different architectures. `x86` is one of them. It was originally designed by Intel. By today `x86` and its extensions are still commonly used. The most popular example is `x86-64` or `amd64`, an extension by AMD.

### Data
The `x86` architecture is a CISC (Complex instruction set computer) architecture. Unlike RISC (Reduced instruction set computer) architectures, CISC computers can execute several more specialized low-level operations, while RISC is a computer with a small, highly optimized set of instructions. Data is stored in memory with little-endian order. The largest value for int, memory address, or register is 16-bit, 32-bit, or 64-bit, depending on the processor generation.

### Processor modes (8080 - x86-64)
Processor modes are various ways how the processor creates an operating environment. The processor mode controls how the processor manages the system memory, the tasks that use it, registers, etc. I listed the most important ones, starting with older ones.
* Real mode flat model (unreal mode) \
&nbsp;– 16-bit architecture \
&nbsp;– CPU can only access 64K at a time (due to 16-bit limitation) \
&nbsp;– your program and its data must exist within a 64K block of memory \
&nbsp;– segment registers are set to the beginning of the memory block by the OS. They won't change as long as the program is running \
&nbsp;– the data of your program isn't really divided into segments \
&nbsp;– it is using 16-bit addresses 
* Real mode segmented model \
&nbsp;– 16-bit architecture \
&nbsp;– CPU can access 1MB (because of using segment selectors, see below) \
&nbsp;– your program and its data can use the full 1MB of memory \
&nbsp;– the programmer has to set the segment registers \
&nbsp;– the data of your program is divided into segments \
&nbsp;– it is using 20-bit addresses. You can access data with `segment:offset`, having them stored in two different registers. You can also use `offset` only, but you can't access data that are at a memory location higher than `0xffff`. 
* Protected mode \
&nbsp;– 32-bit architecture \
&nbsp;– CPU can access over 4GB \
&nbsp;– your program is given a 4GB block of memory \
&nbsp;– the segment registers are managed by the OS and cannot be changed. Their new job is to locate the "flat" segment in virtual memory. \
&nbsp;– 32-bit addresses are used
* Long mode - like protected mode, but everything is 64 bit wide and more memory can be accessed

##### _For compatibility reasons and/or for certain low level operations, modern CPUs can switch into other (older) processor modes_

### Memory segmentation
Memory segmentation is an operating system memory management technique of division of a computer's primary memory into segments or sections. Talking of protected and long mode, you know that every program has its own virtual address space. Inside that is its data and code. The data and code are split into segments (an area in virtual memory for computer use), which are sometimes divided again into sections that are for more specific use (later more). For example, there is the `text` segment, where your code is in. The `data` and `bss` segments are for data, to be more precise, the `data` is for initialized, and the `bss` is for uninitialized variables. The `heap` segment is also used for data. But it is dynamic memory, which means that you can request and release memory from the heap segment. Last but not least there is the `stack segment` or only `stack`, which is also used to store data, especially local variables. It is like a real stack, where you can put something on top of it (called push-operation) and remove something from the top (called pop-operation). You cannot push or pop something from the bottom of the stack which doesn't work in real life either. I will explain later when what is used. This is how it would look like:

![Segments](https://upload.wikimedia.org/wikipedia/commons/thumb/5/50/Program_memory_layout.pdf/page1-225px-Program_memory_layout.pdf.jpg)
### CPU registers
##### The most important ones (user accessible):

| bits | stack-pointer | frame-pointer | general purpose / other |
| --- | --- | --- | --- |
| 16  | sp  | bp  | ax, bx, cx, dx, … |
| 32  | esp | ebp | eax, ebx, ecx, edx, edi, esi, … |
| 64  | rsp | rbp | rax, rbx, rcx, rdx, rdi, rsi, … |
| 128 | \-  | \-  | xmm0, xmm1, xmm2, … |
| 256 | \-  | \-  | ymm0, ymm1, ymm2, … |
| 512 | \-  | \-  | zmm0, zmm1, zmm2, … |

\* Some registers are only present on specific architectures

Most registers are for general use, however, there is the register `rbp`/`ebp`/`bp` (frame/base pointer - points to the current stack frame), `rsp`/`esp`/`sp` (stack pointer - points on the top of the stack), and the `rip`/`eip`/`ip` (instruction pointer - points to the instruction which will be executed by the CPU). After the instruction was executed, the instruction pointer will be incremented to point to the next instruction, if no controlling/control transfer instruction was executed. More on the base pointer and the instruction pointer in the next chapter.

### Call stack
The call stack is an area on the stack for local variables and the return address of a function. These areas are called stackframes. The `rbp` register points to the current stack frame. After a `call` the return address is pushed onto the stack and it is jumped to the specified address. Then the function sets up its stack frame, saves `rbp`, and does its actual job. After that, the stack pointer and the base pointer are restored, and the `ret` instruction is executed. It pops the previously-stored return address into `rip` and continues execution there.

### CPU protection/privilege rings
Computer operating systems provide different levels of access to resources. They are mechanisms to protect data and functionality from faults and malicious behavior. Rings are arranged in a hierarchy from most privileged (most trusted, usually numbered zero) to least privileged (least trusted, usually with the highest ring number). On most operating systems, ring 0 is the level with the most privileges and interacts most directly with the physical hardware such as the CPU and memory (the kernel is in ring 0 of course). Normal applications are usually in the least privileged ring (on Linux in ring 3). In this state, the hardware is pretty much locked up. That's why there are syscalls and interrupts. With them you switch to ring 0 and changes to the hardware can be done.

## The Linux OS and kernel
### Overview
Linux was released in 1991. It is a unix-like operating system. That means that it is not derived from unix, but it is similar. Linux itsELF is not an OS, instead, it's a kernel. Several Linux distributions are all based on the Linux kernel. The standard format for executables is ELF.

### The Linux kernel
The kernel in general is like a program that has full control of the operating system. The kernel is a bridge between the hardware and software. After the bootloader (which is responsible to boot the system) the kernel is the first program loaded on startup. It handles the rest of startup as well as memory and input/output (I/O) requests from software, translating them into data-processing instructions for the CPU. Linux is a monolithic kernel, which means that the kernel not only interacts with the CPU and memory but also has device drivers and other kernel services running in kernel space only (read further for the definition of kernel space). They are best at communicating with hardware and performing several tasks simultaneously. It is for this reason that processes here react at a fast rate. The kernel manages the hardware with interrupts. If we talk about the virtual memory of a program, we divide it into user space and kernel space. In userspace, there is the program code, the data of the program and shared libraries, etc. And in kernel space is data of the kernel. In general, in user space are all the programs and libraries and in kernel space is the whole kernel and its drivers and modules. This applies to Windows too (at least NT based)

### Syscalls and interrupts
When the software or hardware wants to interface with the system, an interrupt is triggered (the hardware sends signals to the CPU through the bus, the software uses the `int` instruction), which interrupts the processor which does the same to the kernel. Interrupts are used for implementing device drivers or transitions between protected modes of operation, such as system calls. The interrupt handler saves the current system state and runs the to the interrupt associated interrupt handling code. After that, the interrupt handler restores the state as it was before the interrupt. When another process requests a service from the kernel, the process has to do a system call. Many different syscalls are doing different things. They are defined in the kernel and they do low-level operations. On 64-bit, they are triggered with a syscall instruction. Before that, the syscall number and the arguments for the syscall are stored in specific registers. When a syscall instruction is executed, the value from the `IA32_LSTAR` register (prepared on kernel boot, only accessible in kernel space / ring zero) is moved into `rip` and jumped to that address (in kernel space). There the register which contains the syscall number is checked and it is jumped to the right syscall code (the address is in the syscall table). After the syscall is finished, you jump back to the instruction following the syscall instruction. Its address was saved earlier in `rcx`. On 32-bit, you use interrupts to jump to the code in kernel space (interrupt handling code) which executes the syscalls (you use `int 0x80`). The addresses of the interrupt handlers are stored in the interrupt vector table. Usually, a program does not use syscalls directly. Instead, wrappers from the shared libraries are used. But there are also other kernel functions, which can't be used by a normal application.

#### Modern exploit mitigation features (kernelspace)
| kernel access layout space randomization (kaslr) | function granular kernel access layout space randomization (fgkaslr) | supervisor mode execution protection (smep) | supervisor mode access prevention (smap) | kernel page table isolisation (kpti) | kernel stack canaries |
| --- | --- | --- | --- | --- | --- |
| The kernel base address is randomized | Per-function randomization | Marking non-kernelspace pages as nonexecutable | Marking non-kernelspace pages as nonaccessible | Separation of user and kernelland pages | Stack-based buffer overflow protection |

### Linux calling convention
#### x86
> 32-bit SYSENTER entry. 32-bit system calls through the VDSO's \_\_kernel\_vsyscall enter here if X86\_FEATURE\_SEP is available. This is the preferred system call entry on 32-bit systems. The SYSENTER instruction, in principle, should _only_ occur in the VDSO. In practice, a small number of Android devices were shipped with a copy of Bionic that inlined a SYSENTER instruction. This never happened in any of Google's Bionic versions – it only happened in a narrow range of Intel-provided versions. SYSENTER loads `ss`, `esp`, `cs`, and `eip` from previously programmed MSRs. IF and VM in RFLAGS are cleared (IOW: interrupts are off). SYSENTER does not save anything on the stack, and does not save old `eip` (!!!), `esp`, or `eflags`. To avoid losing track of EFLAGS.VM (and thus potentially corrupting user and/or vm86 state), we explicitly disable the SYSENTER instruction in vm86 mode by reprogramming the MSRs. Arguments: `eax`: system call number `ebx`: arg1 `ecx`: arg2 `edx`: arg3 `esi`: arg4 `edi`: arg5 `ebp`: user stack `[ebp+0x0]` arg6 Note that for other function calls the arguments are stored on the stack. (conforming to C ABI)

#### x86\_64

> 64-bit SYSCALL instruction entry. Up to 6 arguments in registers. This is the only entry point used for 64-bit system calls. The hardware interface is reasonably well designed and the register to argument mapping Linux uses fits well with the registers that are available when SYSCALL is used. SYSCALL instructions can be found inlined in libc implementations as well as some other programs and libraries. There are also a handful of SYSCALL instructions in the VDSO used, for example, as a clock\_gettimeofday fallback. 64-bit SYSCALL saves `rip` to `rcx`, clears rflags.RF, then saves `rflags` to `r11`, then loads new `ss`, `cs`, and `rip` from previously programmed MSRs (model-specific register). rflags gets masked by a value from another MSR (so CLD and CLAC are not needed). SYSCALL does not save anything on the stack and does not change `rsp`. Registers on entry: `rax`: system call number `rcx`: return address `r11`: saved rflags (note: r11 is callee-clobbered register in C ABI) `rdi`: arg0 `rsi`: arg1 `rdx`: arg2 `r10`: arg3 (needs to be moved to `rcx` to conform to C ABI) `r8`: arg4 `r9`: arg5 (note: `r12`\-`r15`, `rbp`, `rbx` are callee-preserved in C ABI) Only called from userspace.

## ELF file format
### Overview
Since 1999, the ELF file format is the standard executable format on Linux. It defines the structure of binaries, like how they have to look in memory. It allows the operating system to interpret those files.

### Structure
##### Here you can see the structure of an ELF file
lower addresses \
![ELF Structure](https://www.researchgate.net/profile/Wai-Kyi/publication/334531571/figure/fig2/AS:781892970369029@1563429219773/Basic-architecture-of-ELF-file-format-16.ppm) \
higher addresses

The ELF header defines some basic data, like endianness, architecture, version, etc. The ELF header is 52 or 64 bytes long for 32-bit and 64-bit binaries respectively. The program header table tells the system how to create a process image and it specifies for example what needs to be loaded into memory and where. The section header table defines the sections. The segments contain information that is needed for runtime execution of the file, while sections contain important data for linking and relocation.

### How an ELF file is executed
If you execute an ELF file, the kernel first checks the magic bytes (the identifier of an ELF file) to check if the file is an ELF file. Then the kernel gets the basic information of the ELF header, like endianness, etc. From the program header, the kernel determines what segments need to be loaded. Then there is a virtual address space allocated for the process. The segments are created and the segment data is copied to the allocated space (from the file). Then the only thing that is left to do is to jump to the entry point of the program (where the code starts).

### Static versus dynamic binaries
Binaries can either be statically or dynamically compiled. The difference between them is that a dynamic binary relies on system components, to be more specific the shared libraries. Static binaries contain the libraries by themselves, which means they are portable but way bigger than dynamic binaries.

### Shared libraries
Shared libraries are object files that are mapped to the virtual address space of a program. These include code and data the program needs. They are shared between processes, thus they exist only once in the physical address space. The libraries are mapped into various virtual address spaces of programs, which is done by the kernel. On Windows, it's the same principle.

### Modern exploit mitigation features (userspace)

| access layout space randomization (aslr) | process independent executable (pie) | relocation read-only (relro) | stack canaries |
| --- | --- | --- | --- |
| Randomization of shared library and stack addresses etc. | Randomization of the programs base address | Relocating some data to read-only | Protection of buffer overflow |

\* ASLR and PIE is managed by the kernel and the others by the compiler

### The linker, the plt, and the got

The linker combines a number of object and archive files, relocates their data, and ties up symbol references. Usually, the last step in compiling a program is to run the linker. The linker makes use of the section header. If the binary is not static, it has to make use of shared libraries. Programs often use functions that are in shared libraries so they have to call them. But the address of the function is not always known (because of ASLR) and may be different on other systems, so hard-coding the addresses is a bad idea. That is why there are `got` and `plt`. In the `got`, there are the addresses of some functions from the shared libraries which were resolved by the linker and needed by the program. It will also contain important addresses that will be used in the symbol resolution process. _The linker resolves the symbols from the shared libraries._ However, the program doesn't call the addresses in the `got` directly. There is the `plt` where some little functions responsible for each function in the shared libraries are in. They are called by the program and they are calling the actual functions from shared libraries. They also call the linker if the functions have not been resolved yet. When we run a program on Linux, as default behavior, the dynamic linker resolves references to symbols in the shared libraries only when it's needed. In other words, the program doesn't know the address of a specific function in a shared library, until this function is actually referenced. This process of resolving symbols in run-time is known as lazy binding. This amazing picture by syst3mfailure describes it pretty well:

![linker](https://syst3mfailure.io/ret2dl_resolve/assets/images/lazy_binding.png)
*   From the text section, the plt function for read is called
*   From the plt it is jumped to the got. If the symbol has already been resolved, a libc address would be in it.
*   In this case, the symbol hasn't been resolved and we jump back to the plt. Some arguments for the linker are pushed onto the stack and the linker is called. It will resolve the function that we wanted to call earlier and jump to that function.

## The Windows OS and kernel
### Overview
Windows originally was a GUI for MS-DOS. It was created in 1985. Now it is arguably the most popular operating system. The standard file format for executables is PE.

### The Windows kernel
The base principle of how the Windows kernel works is basically the same as the Linux kernel. The only difference is, that some device drivers or other kernel services can be in userspace too. That's why the Windows kernel is a hybrid kernel (a mixture of monolithic (kernel services in kernel space) and microkernel (kernel services in user space)).

### Syscalls and interrupts
Again, the base principle of syscalls and interrupts is the same. They are used to interface with the system. But in Windows, a userspace program will never use interrupts and syscalls directly. That's because the syscall numbers change very often. On Linux, they don't. Because of this reason, you use a library called `ntdll.dll`. It is like the `libc.so.6` in Linux. But you have to use the ntdll library every time you want to do low-level stuff. It handles the syscalls and calls them correctly.

### Modern exploit mitigation features (kernelspace)

| kernel access layout space randomization (kaslr) | supervisor mode execution protection (smep) | supervisor mode access prevention (smap) | kernel page table isolisation (kpti) | kernel data protection (kdp) |
| --- | --- | --- | --- | --- |
| The kernel base address is randomized | Marking non kernel space pages as nonexecutable | Marking non kernel space pages as nonaccessible | Separation of user and kernel land pages | Marking critical kernel pages as readonly |

### Windows calling convention

#### x86-64

| parameter type | arg1 | arg2 | arg3 | arg4 | arg5+ |
| --- | --- | --- | --- | --- | --- |
| float | xmm0 | xmm1 | xmm2 | xmm3 | \[ebp+0x0\] |
| non-float | rcx | rdx | r8  | r9  | \[ebp+0x0\] |

## PE file format

### Overview
The PE file format is the standard executable file format on Windows. It is based on the COFF file format which was used earlier.

### Structure
##### Here you can see the structure of a PE file
lower addresses \
![pe](https://wiki.osdev.org/images/d/dd/PEFigure1.jpg) \
higher addresses

The DOS header is there for compatibility reasons. If we try to execute a PE from DOS on Windows, we get a notification that this application is for DOS. Same the other way around. The MS-DOS real-mode stub program displays this message. The PE header contains information that concerns the entire file. It consists of basic information, like the PE magic. The optional PE header follows directly after the standard PE header. Its size is specified in the PE header which you can also use to tell if the optional header exists. The magic code field can be used in conjunction with the machine type to see in the PE header to detect if the PE file is running on a compatible system. There are a few other useful memory-related variables including the size and virtual base of the code and data, as well as the application's version number, entry point, and how many directories there are. A PE file is made up of sections which consist of a name, offset within the file, virtual address to copy to, as well as the size of the section in the file and in virtual memory (which may differ, in which case the difference should be cleared 0s), and associated flags. Each section has an entry in the section header table.

### Modern exploit mitigation features

| access layout space randomization (aslr) | access layout space randomization for user binaries (like pie) | force aslr | stack canaries |
| --- | --- | --- | --- |
| Randomization of shared library and stack addresses etc. | Randomization of the programs base address | Forced randomization of every programs base address | Protection of buffer overflow |

## Sources

Picture 1: [http://computerscience.gcse.guru/wp-content/uploads/2016/04/Von-Neumann-Architecture-Diagram.jpg](http://computerscience.gcse.guru/wp-content/uploads/2016/04/Von-Neumann-Architecture-Diagram.jpg)
Picture 2: [https://upload.wikimedia.org/wikipedia/commons/thumb/d/dc/MMU\_principle\_updated.png/325px-MMU\_principle\_updated.png](https://upload.wikimedia.org/wikipedia/commons/thumb/d/dc/MMU_principle_updated.png/325px-MMU_principle_updated.png)
Picture 3: [https://upload.wikimedia.org/wikipedia/commons/thumb/5/50/Program\_memory\_layout.pdf/page1-225px-Program\_memory\_layout.pdf.jpg](https://upload.wikimedia.org/wikipedia/commons/thumb/5/50/Program_memory_layout.pdf/page1-225px-Program_memory_layout.pdf.jpg)
Picture 4: [https://www.researchgate.net/profile/Wai-Kyi/publication/334531571/figure/fig2/AS:781892970369029@1563429219773/Basic-architecture-of-ELF-file-format-16.ppm](https://www.researchgate.net/profile/Wai-Kyi/publication/334531571/figure/fig2/AS:781892970369029@1563429219773/Basic-architecture-of-ELF-file-format-16.ppm)
Picture 5: [https://syst3mfailure.io/ret2dl_resolve/assets/images/lazy_binding.png](https://syst3mfailure.io/ret2dl_resolve/assets/images/lazy_binding.png)
Picture 6: [https://wiki.osdev.org/images/d/dd/PEFigure1.jpg](https://wiki.osdev.org/images/d/dd/PEFigure1.jpg)