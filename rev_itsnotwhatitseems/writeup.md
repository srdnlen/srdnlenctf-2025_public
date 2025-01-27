# It's not what it seems

## Challenge Description

The challenge provides the following description:

> "Oh man, I hate self-inverse ciphers."

We are given a binary file to analyze. Opening the file with Ghidra reveals what appears to be a strange encryption algorithm, but something interesting happens when we dig deeper into its behavior during execution.

---

## Initial Analysis

### Observing the Static Behavior

Upon opening the binary in Ghidra, the main function appears to implement a self-inverse cipher. The static analysis shows an encryption function that seems convoluted and overly complicated, making it difficult to understand the actual logic at first glance. The function appears to manipulate the input through various encryption algorithm;

However, this static view does not seem to reflect the actual runtime behavior.

### Dynamic Analysis

To understand the actual behavior of the binary, we can use a debugger (e.g., `gdb`) to step through the execution of the program. Upon closer inspection, that's how we find that the encryption logic observed statically is completely bypassed during execution.

Instead, the binary dynamically performs a simple XOR operation on the input, something like this:

```c
   0x401207 <main+295>: mov    al,BYTE PTR [rsi]
   0x401209 <main+297>: mov    cl,BYTE PTR [rdi]
   0x40120b <main+299>: nop
   0x40120c <main+300>: xor    cl,al
   0x40120e <main+302>: nop
   0x40120f <main+303>: nop
   0x401210 <main+304>: cmp    cl,0x40
   0x401213 <main+307>: nop
   0x401214 <main+308>: nop
   0x401215 <main+309>: nop
   0x401216 <main+310>: nop
   0x401217 <main+311>: jne    0x401394 <main+692>
   0x40121d <main+317>: nop
   0x40121e <main+318>: inc    rsi
   0x401221 <main+321>: inc    rdi
   0x401224 <main+324>: nop
   0x401225 <main+325>: nop
   0x401226 <main+326>: cmp    al,0x3d
   0x401228 <main+328>: nop
   0x401229 <main+329>: jne    0x401207 <main+295>
   0x40122b <main+331>: leave
   0x40122c <main+332>: ret
```

### Key Findings

1. The actual encryption logic dynamically XORs each character of the input with a repeating key.
2. The program then checks the XORed result against a hardcoded expected value.

By knowing this we can retrive the flag.



---
