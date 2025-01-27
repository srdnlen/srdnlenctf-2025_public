# Confusion

- **Category:** Crypto
- **Solves:** -
- **Tag:** Block ciphers

## Description

Looks like our cryptographers had one too many glasses of mirto! Can you sober up their sloppy AES scheme, or will the confusion keep you spinning?

This is a remote challenge, you can connect to the service with: nc confusion.challs.srdnlen.it 1338

## Solution

The randomness of the IV affects only the first two blocks and does not extend further. As a result, the classic ECB oracle attack becomes feasible (where an encryption oracle of the form Enc(msg + FLAG) is available) by simply prepending two fixed blocks to the message.

![photo_5949398448451207850_y](https://github.com/user-attachments/assets/ade1e56e-c73e-4169-b9d7-1a60f35d4510)

```py
from pwn import remote
import string

# Configuration
host, port = "confusion.challs.srdnlen.it", 1338
pad_blocks = 5
n_blocks = pad_blocks + 1

# Establish connection
r = remote(host, port)
flag = b""

for max_len in range(60):
    # Prepare input padding
    first_pad = b"00" * (16 * (pad_blocks + 1) - len(flag) - 1)
    second_pad = first_pad + flag.hex().encode()
    
    # Get the targetencrypted block
    r.recvuntil(b"(hex)")
    r.sendline(first_pad)
    r.recvuntil(b"encryption")
    r.recvuntil(b"|")
    r.recvuntil(b"| ")
    enc = c.recvline().strip()
    target= enc[2 * 16 * n_blocks:]
    
    # Brute force to find the next character
    for ch in string.printable:
        r.recvuntil(b"(hex)")
        r.sendline(second_pad + ch.encode().hex().encode())
        r.recvuntil(b"encryption")
        r.recvuntil(b"|")
        r.recvuntil(b"| ")
        enc = r.recvline().strip()
        res = enc[2 * 16 * n_blocks:]
        
        # Check if the block matches
        if res == target:
            flag += ch.encode()
            print(flag)
            break

c.interactive()
```

