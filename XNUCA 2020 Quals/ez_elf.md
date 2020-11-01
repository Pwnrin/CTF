# ez_elf
**First Blood**

通过远程给的当前dump的内存恢复程序并运行，运行得到answer并输入即得flag

思路比较简单:直接mmap相应的内存，而后直接在内存中固定GOT的值，而后跳转到main函数地址即可

## EXP:
```
//gcc magic.c -o exp -pthread
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <gnu/lib-names.h>
#include <termios.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h> 
#include <sys/xattr.h>
#include <sys/stat.h>
#include <sys/resource.h>


void (*main_func)(int, char **, char**);

int main(int argc, char **args, char **envp)
{
    char *image_base, **magic;
    int fd;

    fd = open("./1", 0);

    image_base = mmap(0x400000, 0x17000, PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    read(fd, image_base, 0x17000);
    mmap(image_base + 0x216000, 0x3000, PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    read(fd, image_base + 0x216000, 0x3000);

    magic = image_base + 0x617018-0x400000;
    int i=0;
    magic[i++]=unlink;
    magic[i++]=strcpy;
    magic[i++]=puts;
    magic[i++]=fread;
    magic[i++]=shmdt;
    magic[i++]=write;
    magic[i++]=fclose;
    magic[i++]=alarm;
    magic[i++]=read;
    magic[i++]=srand;
    magic[i++]=calloc;
    magic[i++]=strtoll;
    magic[i++]=memcpy;
    magic[i++]=__xstat;
    magic[i++]=malloc;
    magic[i++]=setrlimit;
    magic[i++]=0x7ffff78f7380; // Without ALSR
    magic[i++]=setvbuf;
    magic[i++]=removexattr;
    magic[i++]=shmctl;
    magic[i++]=fopen;
    magic[i++]=shmat;
    magic[i++]=shmget;
    magic[i++]=getxattr;
    magic[i++]=exit;
    magic[i++]=fwrite;
    magic[i++]=0x7ffff78f7570; // Without ALSR
    magic[i++]=setxattr;
    magic[i++]=sleep;
    magic[i++]=fork;
    magic[i++]=usleep;

    magic = image_base + 0x617120-0x400000;
    magic[0] = stdout;
    magic[2] = stdin;
    magic[4] = stderr;

    main_func = image_base + 0x400da0-0x400000;

    mprotect(image_base, 0x6000, PROT_READ|PROT_EXEC);
    mprotect(image_base + 0x216000, 0x3000, PROT_READ|PROT_WRITE);

    main_func(argc, args, envp);
    return 0;
}
```
```
from pwn import *
import os
context.log_level="debug"
p=remote("123.57.4.93",23334)
p.recvuntil("Start:\n")
s1=p.recvuntil("End.")[:-5]
p.recvuntil("Start:\n")
s2=p.recvuntil("End.")[:-5]
p.recvuntil("Start:\n")
s3=p.recvuntil("End.")[:-5]
f=open("1.xz","wb")
f.write((s1+s2+s3).decode("base64"))
f.close()
os.system("xz -d ./1.xz")
p.interactive()
```