# Kinderheim 511

**CTF:** Srdnlen CTF 2025\
**Category:** pwn\
**Difficulty:** Medium-Hard\
**Solves:** TBA\
**Author:** Matteo Cornacchia <@zoop>

---

## Description

> Long live the expo. No wait, I mixed that one up.

The challenge consists of an ELF binary, also running on a remote TCP endpoint.
The binary is a fairly typical heap challenge setup with options to create, delete and read the contents of small data sections. 
The flag is loaded in a heap chunk which is kept inaccessible to the read option.

## Solution

Because of a discrepancy in the control flow between freeing the chunks and zeroing out their entry, it is possible to create a double free by freeing a block in a slot further than the earliest zeroed slot more than once.

In order to leverage this bug on glibc 2.35, you will first need to fill the tcache with unused chunks. Then the extra blocks freed will end up in the fastbin, where they can be duplicated almost without restrictions. Once there, you can then reallocate all blocks in memory to obtain the same pointer twice. 

When moving back the allocated blocks to tcache, the chunk pointer is xored with the memory page of the heap as a mild security safeguard. 
You will need a heap leak, which can be easily generated in a way very similar to the double free, by reallocating a zeroed slot and reading a freed (but not zeroed) chunk after it.

Once we have leveraged the double free and we have correctly adjusted the pointer value, all we need to do is overwrite the heap location of the "records" so that a further slot will contain the value of slot #0, containing the flag. Then we can use the regular binary functionality to read the flag.

An example exploit using this technique is available at `src/solve.py`.

This exploit does not use a few other minor bugs in the binary. For instance, it is possible to build a completely separate exploit based on corrupting an existing chunk pointer with a null byte poisoning to allocate an overlapping chunk. At least 2 teams chose this approach and their exploit was published on the CTF discord.

It also does not reach full RCE. If you have a solution that does, feel free to reach out to me on Discord.
