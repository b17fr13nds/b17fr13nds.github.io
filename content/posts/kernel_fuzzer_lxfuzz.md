+++ 
draft = false
date = 2024-09-07T18:11:00+02:00
title = "My own kernel fuzzer - lxfuzz"
description = "Writing a kernel fuzzer from scratch"
slug = ""
authors = ["bitfriends"]
tags = ["fuzzing","linux","kernel"]
categories = ["projects"]
externalLink = ""
series = []
+++

My long-term project is writing a kernel fuzzer named lxfuzz. It is a coverage-guided fuzzer for the linux kernel. I chose that project for some reasons:
- To learn about fuzzing, its mechanisms etc. in general
- To learn more about the linux kernel, especially 
- To improve my C++ skills :) (the language used for lxfuzz)
- Profit (finding CVEs)

Under the hood it's using qemu to run the kernel and KCOV for coverage collection.
The project is still work-in-progress and developed gradually.
Current features are:
- Testing syscalls, char devices, sockets, ...
- Running multiple instaces each assigned cpu cores and memory
- Freedom in running the kernel, highly configurable
- Coverage collection through the kcov framework
- Using hypercalls for fast data transfer between guest and host
- A basic mutator and logging functionality
- Kernel panic saving and a crash reproducer
- Making use of user namespaces and/or running as a daemon
- And more to come

You can find the current state of development on [GitHub](https://github.com/b17fr13nds/lxfuzz) as well as some more info. 
Feel free to reach out on me for any questions/advice/etc. :)