# A child's dream

**CTF:** Srdnlen CTF 2025 Quals\
**Category:** pwn\
**Difficulty:** Insane\
**Authors:** @davezero (Davide Maiorca) & @church (Matteo Chiesa)

## Description

> In 1990, a new console was released in Japan.\
The beginning of a new era, of a child's dream,\
Where exploits were still unknown,\
And a new world was yet to be discovered.

## Overview

This challenge is a ROM of the game `breakout` of the SNES console. It contains a redacted flag, so the goal is understand how to print it on screen just playing the game, to do the same on the online instance, that has the real flag.

## Solution

To play and analyze this ROM, we can use **[Mesen](https://www.mesen.ca/), a free multi-platform SNES emulator with a debugger included**.

### Play the game

First let's try the game, and test the normal behavior of the keys. The most notable are `LEFT` and `RIGHT`, that move the player, and keeping pressed `A` the movement is faster. The `L` key ends the game, while all other keys seems to have no evident behaviors except for **`R`; when is pressed the game seems to crash**. This is suspicous, surely we have to investigate the internal behavior of this key.

### Binary analysis

Via the Mesen memory viewer, we can search for the string `srdnlen{__REDACTED__FLAG__}` to get its address, which is `0xD658`. Then, moving to the debugger, we can search the value `D658` in the assembly, to see if the flag is referenced by any function; we hit on result at the address `0xDEEE`, in the function at the location `0xDEDF`. In fact **executing this function will prints the flag on the screen**, but in the online instance we haven't a debugger, so we have to search for some vulnerability to exploit and through that run the "win" function.

Now we can try to reverse some of the code, and hope to understand also the `R` key question.

To search where to start in the code, we can try to **understand the input handling on SNES**. On the internet we can find various wikies like [this](https://en.wikibooks.org/wiki/Super_NES_Programming/Joypad_Input), that indicates that the current states of the keys pressed on the first joypad are saved on `$4016` or `$4218`. In the first address we can't see anything, but the second changes according to our input. From that we can map the values of all the keys:
```
KEY_R = 16
KEY_L = 32
KEY_X = 64
KEY_A = 128
KEY_RIGHT = 256
KEY_LEFT = 512
KEY_DOWN = 1024
KEY_UP = 2048
KEY_START = 4096
KEY_SELECT = 819
KEY_B = 32768
KEY_Y = 16384
```
This table is also in the [same wiki linked before](https://en.wikibooks.org/wiki/Super_NES_Programming/Joypad_Input), but in a strange format.

Searching if the address of the pressed keys is used in the assembly, we found nothing interesting, so the input are stored even in another address; but we can search for the value of the keys, and we're gonna end up in the function that handle the input for this specific game, the one that modifies the player position accordingly with the input.\
With this we have more luck, because lots of the keys values are in the `0x0CAC`
function, used in the `AND #$` operator to check the correct bit. This function is pretty long, but the first part seems to be the **game input handler**. This is confirmed using some breakpoints. Reversing this function will reveal a lot.

First we can take a look at the `R` crash.\
Searching for `AND #$0010` reveals the interesting part: when `R` is pressed, it call the `0x018301` function; reversing that, it turns out to be a `memcpy` function! This call will copy 3 bytes from `0x7F0000` to the stack address `0x1FF9`, but the allocated memory in the stack is only of 1 byte, so **this will overflow the stack!**. Immediately after the 1 byte of allocated memory in the stack, there is the return address, that is 2 bytes long, so this is gonna overwrite it. If only we find a method to modify the values at `0x7F0000`...

Analyzing deeper the input handler function, we can see that also the `UP` and `DOWN` keys have some behavior, because there are same lines like `AND #$0400`. Reversing that part, we uncover that this ends up to increment or decrement the values in `0x7F0000`, based on the index stored at `0x7E3292`. And this index is referenced also in other parts of the same input handler, because it increments and decrements using the `LEFT` and `RIGHT` keys (but remains between 0 and 2). So we can change however we want the `0x7F0000` buffer, and then we can copy it on the stack, overflowing it.

### Expoit the game

So we have all we need. We want to write in the last 2 bytes of the `0x7F0000` buffer the address `0xDEDF`, to jump there and so print the flag.\
We can do it via the debugger to do some tries, and we notice that we have to write it in little endian, and we don't have to write exacly `0xDEDF`, but `0xDEDE`, because automatically the SNES add 1 to that. So the buffer wil look like `00 DE DE`. Pressing `R`, and there's the flag.

Now we have to write it without the debugger, but using `UP`, `DOWN`, `LEFT` and `RIGHT`. From the input handler, we can notice also that keep pressing `A` affects also the `UP` and `DOWN`, because increment the buffer values by 0x10, and not 1. So there's the input we have to do:
```
RIGHT        # to move the index to the second byte of the buffer
A + DOWN    # to decrement the second byte of the buffer to F0
A + DOWN    # to decrement the second byte of the buffer to E0
DOWN        # to decrement the second byte of the buffer to DF
DOWN        # to decrement the second byte of the buffer to DE
RIGHT        # to move the index to the third byte of the buffer
A + DOWN    # to decrement the third byte of the buffer to F0
A + DOWN    # to decrement the third byte of the buffer to E0
DOWN        # to decrement the third byte of the buffer to DF
DOWN        # to decrement the third byte of the buffer to DE
R           # to copy the buffer in the stack and trigger the overflow
```
These inputs are not the actual inputs that you're gonna send, because in the meantime you have to play the manche, or the buffer's gonna reset to 0s, but these are the inputs important for the exploit.

Once you solve that, you just have to do the same on the online instance, where the flag is not redacted:

**srdnlen{l0ng_l1f3_t0_sn3s!}**

