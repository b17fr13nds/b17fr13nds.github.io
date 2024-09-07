+++
title = 'my own kernel fuzzer - lxfuzz'
date = 2024-09-07T18:11:00+02:00
draft = false
+++

my long-time project is writing a kernel fuzzer named lxfuzz. it is a coverage-guided fuzzer for the linux kernel. I chose that project for some reasons:
- to learn about fuzzing, its mechanisms etc. in general
- to learn more about the linux kernel, especially 
- to improve my C++ skills :) (the language used for lxfuzz)
- profit (finding CVEs)

undert the hood it's using qemu to run the kernel and kcov for coverage collection.
the project is still work-in-progress and developed gradually.
the current features are:
- testing syscalls, char devices, sockets, ...
- running multiple instaces each assigned cpu cores and memory
- freedom in running the kernel, highly configurable
- coverage collection through the kcov framework
- using hypercalls for fast data transfer between guest and host
- a basic mutator and logging functionality
- kernel panic saving and a crash reproducer
- making use of user namespaces and/or running as a daemon
- and more to come

you can find the current state of development on [GitHub](https://github.com/b17fr13nds/lxfuzz) as well as some more info. 
feel free to reach out on me for any questions/advice/etc. :)