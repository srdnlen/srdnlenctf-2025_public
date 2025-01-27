# Snowstorm

**CTF:** Srdnlen CTF 2025 Quals\
**Category:** misc\
**Difficulty:** Hard\
**Author:** @church (Matteo Chiesa)

## Description

> I NEED to tell you about my terrible experience with that cheese, ALL OF YOU need to know! I will post my experience on my blog, but first I have to write it on my Windows PC using Visual Studio Code.

### Readme file

> Solving this challenge, keep in mind that the blog post is been writed in a **`.txt` document** on **Visual Studio Code** on **Windows**, with **NUM LOCK enabled**.

## Overview

This challenge is a PCAP file of USB traffic between a keyboard and a PC. The traffic rapresent the keystrokes pressed writing the blog post. We can imagine that the flag is been written within the blog post, or more generally is been written on the keyboard during the traffic recording, so we can proceed to analyse the PCAP file and trying to recover what is been written on this keyboard. 

## Solution

### PCAP analysis

The data of the keystokes are in the last 8 bytes of the `USB INTERRUPT` packets from the device to the host. In it, the first one is reserved for the keys used in shortcuts, like `CTRL` and `SHIFT`, and from the third to the last byte indicates which normal keys are pressed.

While each shortcut keys have associated a reserved bit in the first bytes of the array, each key is rapresented by a specific 1-byte value, called **scan code**. Assuming that the keyboard layout used is the international one, we can find the complete table in the document published at [this address](https://www.usb.org/document-library/hid-usage-tables-15).

We can already proceed to parse the PCAP, extracting the scan codes. To do this we can use `tshark`, with the command:
```sh
tshark -r cheese_with_friends.pcap -Y '(usb.data_len == 8) && (usb.dst == "host")' -Tfields -e usbhid.data | sed 's/../:&/g2' > keyboard.txt
```
This returns a file with only the scan codes in hex, with each byte separated by a `:`.

### Keyboard discovery

Online we can found some tools like [this usb keyboard parser](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser), that can parse the file we have created, assembling what is been typed on the keyboard. Trying to run it, we can notice that the scan codes used by the keyboard aren't banal: in the input are pressed the `BACKSPACE`, the arrows, some numpad keys and other more unusual keys.

Exploring deeper into the data, we can also notice that are used `CTRL`, `SHIFT` and `ALT` either left and right, with either classical and more obscure shortcut, from the `CTRL+X` to `CTRL+SHIFT+L`.\
Here we can see the reason of some of the indications for this challenge: some of the shortcuts used don't have a uniform behavior, but specifying the environment they fall back into a precise action.

In the keyboard we can also recognize a Windows pecularity: the numpad keys pressed with the `ALT` key; this combination is used to write any ASCII symbol by its value. And this is the reason of the indication about the `NUMLOCK`.

### A prorammatic way

This seems to be a programming challenge: we have access to the default behavior of all the VSCode shortcuts (they are also published at [this address](https://code.visualstudio.com/shortcuts/keyboard-shortcuts-windows.pdf)), so we have just to handle correctly all the keyboard input, and map it to do the correct operation on the file, right?

Well, yes, it is a solution. But it is the most elegant one? Doing that can be tedious and boring.\
We can try to search in the values for an open curly bracket `{` to identify the flag, and parse the input little before and after, to get only the flag. But if we doing that, we can notice that the curly brackets are never typed, not even with `ALT+123` on numpad, that correspond to the same character; so where is the flag? Seems that what is written is more complicated that hoped. And if the flag is written in a complicated method, maybe even a little error parsing the inputs can lead to a result without the flag.

### Reproduce the keyboard

But we can think another, more clever solution. What if we write a code that reproduce the input of the keyboard? Doing that, we can simply position the cursor on an empty document in VSCode, run our script, and the shortcuts are handled by VSCode itself.\
To reproduce the keyboard there are lots of Python libraries, but the most granular I found is [Pynput](https://pypi.org/project/pynput/), that can handle in a simple way the only press and the only release operations of a key. We can then write a script that parse the keyboard file, and from those data we have to recover the newly pressed or released keys at each moment, to do the same in our machine.

We can start by map each scan code to the corresponding letter, using also the constant defined by Pynput:
```py
from pynput.keyboard import Key

KEYMAP_INTL = {
    0x04: "a",
    0x05: "b",
    0x06: "c",
    0x07: "d",
    0x08: "e",
    0x09: "f",
    0x0A: "g",
    0x0B: "h",
    0x0C: "i",
    0x0D: "j",
    0x0E: "k",
    0x0F: "l",
    0x10: "m",
    0x11: "n",
    0x12: "o",
    0x13: "p",
    0x14: "q",
    0x15: "r",
    0x16: "s",
    0x17: "t",
    0x18: "u",
    0x19: "v",
    0x1A: "w",
    0x1B: "x",
    0x1C: "y",
    0x1D: "z",
    0x1E: "1",
    0x1F: "2",
    0x20: "3",
    0x21: "4",
    0x22: "5",
    0x23: "6",
    0x24: "7",
    0x25: "8",
    0x26: "9",
    0x27: "0",
    0x28: Key.enter,
    0x29: Key.esc,
    0x2A: Key.backspace,
    0x2B: Key.tab,
    0x2C: " ",
    0x2D: "-",
    0x2E: "=",
    0x2F: "[",
    0x30: "]",
    0x31: "\\",
    0x32: "#",
    0x33: ";",
    0x34: "\'",
    0x35: "`",
    0x36: ",",
    0x37: ".",
    0x38: "/",
    0x39: Key.caps_lock,
    0x3A: Key.f1,
    0x3B: Key.f2,
    0x3C: Key.f3,
    0x3D: Key.f4,
    0x3E: Key.f5,
    0x3F: Key.f6,
    0x40: Key.f7,
    0x41: Key.f8,
    0x42: Key.f9,
    0x43: Key.f10,
    0x44: Key.f11,
    0x45: Key.f12,
    # 0x46: Key.print_screen,
    # 0x47: Key.scroll_lock,
    # 0x48: Key.pause,
    0x49: Key.insert,
    0x4A: Key.home,
    # 0x4B: Key.page_up,
    0x4C: Key.delete,
    0x4D: Key.end,
    # 0x4E: Key.page_down,
    0x4F: Key.right,
    0x50: Key.left,
    0x51: Key.down,
    0x52: Key.up,
    0x53: Key.num_lock,
    0x54: "/",
    0x55: "*",
    0x56: "-",
    0x57: "+",
    0x58: Key.enter,
    0x59: "1",
    0x5A: "2",
    0x5B: "3",
    0x5C: "4",
    0x5D: "5",
    0x5E: "6",
    0x5F: "7",
    0x60: "8",
    0x61: "9",
    0x62: "0",
    0x63: ".",
    0x64: "\\",
}

KEYMAP_COMBO = {
    0b00000001: Key.ctrl_l,
    0b00000010: Key.shift_l,
    0b00000100: Key.alt_l,
    0b00001000: Key.cmd_l,
    0b00010000: Key.ctrl_r,
    0b00100000: Key.shift_r,
    0b01000000: Key.alt_gr,
    0b10000000: Key.cmd_r,
}
```

Some keys are commented because they don't make any change to the written text, or they are display-dependent, so their behavior is not fixed.

Then we can write the actual script\
**⚠️ WARNING ⚠️: after 3 seconds the launch of this script, your computer starts to receive actual keyboard input, so you have 3 seconds to move your cursor to an empty document, to handle all these inputs.**

```py
import time
from pynput.keyboard import Controller

def main():
    # Open keyboard file
    INITIAL_DELAY = 3
    DELAY = 0.02
    KEYBOPARD_FILE = 'keyboard.txt'
    with open(KEYBOPARD_FILE, "r") as file:
        keystrokes = file.readlines()

    # Wait to position the cursor on an empty document
    time.sleep(INITIAL_DELAY)

    # Init variables...
    keyboard = Controller()
    old_pressed_keys = set()

    # For each interrupt
    for line in keystrokes:
        if stripped := line.strip():

            # Convert values from hex-str to int
            stroke = [int(byte, 16) for byte in stripped.split(":")]
            print(stroke)

            # Skip data overflow
            if stroke[2] == 0x1: continue

            # Capture all keys pressed in a single interrupt
            pressed_keys = set()

            # Check combokeys
            for code, key in KEYMAP_COMBO.items():
                if stroke[0] & code:
                    pressed_keys.add(key)

            # Check other keys
            for key in stroke[2:]:
                if key == 0:
                    break
                pressed_keys.add(KEYMAP_INTL[key])

            # Get newly pressed and newly released keys
            new_pressed_keys = pressed_keys - old_pressed_keys
            new_released_keys = old_pressed_keys - pressed_keys
            old_pressed_keys = pressed_keys

            # For each newly pressed key, press it
            for key in new_pressed_keys:
                print(f"PRESS {key}")
                keyboard.press(key)
                
            # For each newly released key, release it
            for key in new_released_keys:
                print(f"RELEASE {key}")
                keyboard.release(key)

            # Add a bit of delay between each input
            time.sleep(DELAY)
```

Running this script in a Windows system and positioning the cursor on an empty VSCode document, we can already see great result: the text is written fluently, and the majority of the shortcuts are handle correctly. But sadly have had no flag, and we had a weird behavior after all those symbols, we can see some substitutions and other things done with the VSCode shortcuts; probably the flag is hidden there.

### Analysis of the problems

To a better analysis, we can add a stop key (like `F9`, which isn't used), so when we press that, the script ends forcedly.
```py
import os
from pynput.keyboard import Listener

def main():
    ...
    # Wait to position the cursor on an empty document
    time.sleep(INITIAL_DELAY)

    # Define stop key
    def on_press(key):
        if key == Key.f9:
            for key in KEYMAP_COMBO.values():
                keyboard.release(key)
            os._exit(1)

    listener = Listener(on_press=on_press)
    listener.start()

    # Init variables...
    ...
```

Analyzing more carefully want is been written, we can see that the numpad is not handled properly, and the numpad keys haven't their constant to represent them, because it depends from the OS. We can work around that taking the value from the Virtual Keys that Pynput offers for Windows.
```py
from pynput.keyboard import Key, KeyCode
import pynput._util.win32_vks as VK

KEYMAP_INTL = {
    ...
    0x54: KeyCode(vk=VK.DIVIDE),
    0x55: KeyCode(vk=VK.MULTIPLY),
    0x56: KeyCode(vk=VK.SUBTRACT),
    0x57: KeyCode(vk=VK.ADD),
    0x58: Key.enter,
    0x59: KeyCode(vk=VK.NUMPAD1),
    0x5A: KeyCode(vk=VK.NUMPAD2),
    0x5B: KeyCode(vk=VK.NUMPAD3),
    0x5C: KeyCode(vk=VK.NUMPAD4),
    0x5D: KeyCode(vk=VK.NUMPAD5),
    0x5E: KeyCode(vk=VK.NUMPAD6),
    0x5F: KeyCode(vk=VK.NUMPAD7),
    0x60: KeyCode(vk=VK.NUMPAD8),
    0x61: KeyCode(vk=VK.NUMPAD9),
    0x62: KeyCode(vk=VK.NUMPAD0),
    0x63: KeyCode(vk=VK.DECIMAL),
    0x64: "\\",
}
```

This was a step forward, but it is not enough. We can see that the numpad is not perfect, and more precisely we can notice that this technique fails to handle correctly the `SHIFT+numpad` situation when `NUMLOCK` is on. Normally, in this scenario the numpad changes its behavior like the `NUMLOCK` temporarily deactivate, but in the script it doesn't. Let's fix this.
```py
NUMPAD_TO_FUNC = {
    VK.NUMPAD1: Key.end,
    VK.NUMPAD2: Key.down,
    # VK.NUMPAD3: Key.page_down,
    VK.NUMPAD4: Key.left,
    VK.NUMPAD6: Key.right,
    VK.NUMPAD7: Key.home,
    VK.NUMPAD8: Key.up,
    # VK.NUMPAD9: Key.page_up,
    VK.NUMPAD0: Key.insert,
    VK.DECIMAL: Key.delete,
}

def main():
    ...
    # Init variables
    numlock = True # Initial numlock
    ...
            # For each newly pressed key, press it
            for key in new_pressed_keys:

                # Handle numlock
                restore_shift = None
                if key == Key.num_lock:
                    numlock = (not numlock)

                # Handle keypad
                elif isinstance(key, KeyCode) and (VK.NUMPAD0 <= key.vk <= VK.NUMPAD9 or key.vk == VK.DECIMAL):
                    tmp_numlock = numlock
                    if tmp_numlock and ((Key.shift_l in pressed_keys) or (Key.shift_r in pressed_keys)):
                        tmp_numlock = False
                        if Key.shift_l in pressed_keys:
                            keyboard.release(Key.shift_l)
                            restore_shift = Key.shift_l
                        elif Key.shift_r in pressed_keys:
                            keyboard.release(Key.shift_r)
                            restore_shift = Key.shift_r
                    if not tmp_numlock:
                        key = NUMPAD_TO_FUNC.get(key.vk, None)
                        
                # Press keys
                if key:
                    print(f"PRESS {key}")
                    keyboard.press(key)
                if restore_shift:
                    keyboard.press(restore_shift)
                
            # For each newly released key, release it
            for key in new_released_keys:
                if isinstance(key, KeyCode) and (VK.NUMPAD0 <= key.vk <= VK.NUMPAD9 or key.vk == VK.DECIMAL):
                    if key_ := NUMPAD_TO_FUNC.get(key.vk, None):
                        keyboard.release(key_)

                print(f"RELEASE {key}")
                keyboard.release(key)
            ...
```

### Final script

After this fix, all comes together. Now all the key are handle correctly and now we can see why the flag seems is not there: it's written as an ASCII Art!

**srdnlen{R0t73n_5H0r7Cu75}**

Here the final text:
```
Blog #17

Title: My Unsettling Encounter with Casu Martzu.

I had always considered myself an adventurous eater, eager to try the world's most exotic delicacies.
When I visited Sardinia, the promise of experiencing Casu Martzu - the infamous "rotten cheese", teeming with live maggots - felt like a once-in-a-lifetime opportunity. This wasn't just food; it was a cultural ritual, steeped in tradition and controversy.
However, nothing could prepare me for the reality of facing that wiggling block of pecorino. As the host ceremoniously removed the covering, revealing the cheese alive with larvae, my confidence began to waver.
The smell hit first: a potent, ammonia-like aroma mixed with a hint of decay. My stomach tightened as I stared down at the challenge on my plate, unsure if I could muster the courage.

When I finally worked up the nerve to take a bite, it was an experience like no other. The taste was a sharp assault on my senses: intensely tangy, rich, and bitter all at once.
I could feel a slight crunch that I tried hard to ignore. I told myself it was part of the cheese's crust, but deep down, I knew better.
To make matters more surreal, I had to constantly guard my plate because the larvae were capable of jumping several inches high. My dining companions laughed, calling it the "dancing cheese", but my nerves were frayed. It wasn't just a meal, it was a gauntlet.

The texture, though creamy, was complicated by the knowledge of its tiny inhabitants. It seems like this:
                _         _                 __ ____    ___   _   _____  _____              ____   _   _   ___        _____  ____       _____  ____ __   
  ___  _ __  __| | _ __  | |  ___  _ __    / /|  _ \  / _ \ | |_|___  ||___ /  _ __       | ___| | | | | / _ \  _ __|___  |/ ___|_   _|___  || ___|\ \  
 / __|| '__|/ _` || '_ \ | | / _ \| '_ \  | | | |_) || |_| || __|  / /   |_ \ | '_ \      |___ \ | |_| || |_| || '__|  / /| |   | | | |  / / |___ \ | | 
 \__ \| |  | (_| || | | || ||  __/| | | |< <  |  _ < | |_| || |_  / /   ___) || | | |      ___) ||  _  || |_| || |    / / | |___| |_| | / /   ___) | > >
 |___/|_|   \__,_||_| |_||_| \___||_| |_| | | |_| \_\ \___/  \__|/_/   |____/ |_| |_|_____|____/ |_| |_| \___/ |_|   /_/   \____|\__,_|/_/   |____/ | | 
                                           \_\                                      |_____|                                                        /_/  


Even hours later, I couldn't shake the feeling of Casu Martzu. The taste lingered in my mouth, and my mind replayed the scene like a slow-motion horror film.
Reflecting on it now, I'm not entirely sure if I regret the experience or cherish it for its sheer audacity.
This cheese is banned in many countries for safety reasons, and after trying it, I understand why. But in a strange way, I also respect the Sardinian people for preserving such a raw and unapologetic tradition.
Eating Casu Martzu was disconcerting, to say the least, but it was also an unforgettable reminder of how food can push the boundaries of culture, comfort, and even courage.

by @Church
```

Here is the final script:
```py
import time
import os
from pynput.keyboard import Key, KeyCode, Controller, Listener
import pynput._util.win32_vks as VK

def main():
    # Open keyboard file
    INITIAL_DELAY = 3
    DELAY = 0.02
    KEYBOPARD_FILE = 'keyboard.txt'
    with open(KEYBOPARD_FILE, "r") as file:
        keystrokes = file.readlines()

    # Wait to position the cursor on an empty document
    time.sleep(INITIAL_DELAY)

    # Define stop key
    def on_press(key):
        if key == Key.f9:
            for key in KEYMAP_COMBO.values():
                keyboard.release(key)
            os._exit(1)

    listener = Listener(on_press=on_press)
    listener.start()

    # Init variables...
    numlock = True
    keyboard = Controller()
    old_pressed_keys = set()

    # For each interrupt
    for line in keystrokes:
        if stripped := line.strip():

            # Convert values from hex-str to int
            stroke = [int(byte, 16) for byte in stripped.split(":")]
            print(stroke)

            # Skip data overflow
            if stroke[2] == 0x1: continue

            # Capture all keys pressed in a single interrupt
            pressed_keys = set()

            # Check combokeys
            for code, key in KEYMAP_COMBO.items():
                if stroke[0] & code:
                    pressed_keys.add(key)

            # Check other keys
            for key in stroke[2:]:
                if key == 0:
                    break
                pressed_keys.add(KEYMAP_INTL[key])

            # Get newly pressed and newly released keys
            new_pressed_keys = pressed_keys - old_pressed_keys
            new_released_keys = old_pressed_keys - pressed_keys
            old_pressed_keys = pressed_keys

            # For each newly pressed key, press it
            for key in new_pressed_keys:

                # Handle numlock
                restore_shift = None
                if key == Key.num_lock:
                    numlock = (not numlock)

                # Handle keypad
                elif isinstance(key, KeyCode) and (VK.NUMPAD0 <= key.vk <= VK.NUMPAD9 or key.vk == VK.DECIMAL):
                    tmp_numlock = numlock
                    if tmp_numlock and ((Key.shift_l in pressed_keys) or (Key.shift_r in pressed_keys)):
                        tmp_numlock = False
                        if Key.shift_l in pressed_keys:
                            keyboard.release(Key.shift_l)
                            restore_shift = Key.shift_l
                        elif Key.shift_r in pressed_keys:
                            keyboard.release(Key.shift_r)
                            restore_shift = Key.shift_r
                    if not tmp_numlock:
                        key = NUMPAD_TO_FUNC.get(key.vk, None)
                        
                # Press keys
                if key:
                    print(f"PRESS {key}")
                    keyboard.press(key)
                if restore_shift:
                    keyboard.press(restore_shift)
                
            # For each newly released key, release it
            for key in new_released_keys:
                if isinstance(key, KeyCode) and (VK.NUMPAD0 <= key.vk <= VK.NUMPAD9 or key.vk == VK.DECIMAL):
                    if key_ := NUMPAD_TO_FUNC.get(key.vk, None):
                        keyboard.release(key_)

                print(f"RELEASE {key}")
                keyboard.release(key)

            # Add a bit of delay between each input
            time.sleep(DELAY)


KEYMAP_INTL = {
    0x04: "a",
    0x05: "b",
    0x06: "c",
    0x07: "d",
    0x08: "e",
    0x09: "f",
    0x0A: "g",
    0x0B: "h",
    0x0C: "i",
    0x0D: "j",
    0x0E: "k",
    0x0F: "l",
    0x10: "m",
    0x11: "n",
    0x12: "o",
    0x13: "p",
    0x14: "q",
    0x15: "r",
    0x16: "s",
    0x17: "t",
    0x18: "u",
    0x19: "v",
    0x1A: "w",
    0x1B: "x",
    0x1C: "y",
    0x1D: "z",
    0x1E: "1",
    0x1F: "2",
    0x20: "3",
    0x21: "4",
    0x22: "5",
    0x23: "6",
    0x24: "7",
    0x25: "8",
    0x26: "9",
    0x27: "0",
    0x28: Key.enter,
    0x29: Key.esc,
    0x2A: Key.backspace,
    0x2B: Key.tab,
    0x2C: " ",
    0x2D: "-",
    0x2E: "=",
    0x2F: "[",
    0x30: "]",
    0x31: "\\",
    0x32: "#",
    0x33: ";",
    0x34: "\'",
    0x35: "`",
    0x36: ",",
    0x37: ".",
    0x38: "/",
    0x39: Key.caps_lock,
    0x3A: Key.f1,
    0x3B: Key.f2,
    0x3C: Key.f3,
    0x3D: Key.f4,
    0x3E: Key.f5,
    0x3F: Key.f6,
    0x40: Key.f7,
    0x41: Key.f8,
    0x42: Key.f9,
    0x43: Key.f10,
    0x44: Key.f11,
    0x45: Key.f12,
    # 0x46: Key.print_screen,
    # 0x47: Key.scroll_lock,
    # 0x48: Key.pause,
    0x49: Key.insert,
    0x4A: Key.home,
    # 0x4B: Key.page_up,
    0x4C: Key.delete,
    0x4D: Key.end,
    # 0x4E: Key.page_down,
    0x4F: Key.right,
    0x50: Key.left,
    0x51: Key.down,
    0x52: Key.up,
    0x53: Key.num_lock,
    0x54: KeyCode(vk=VK.DIVIDE),
    0x55: KeyCode(vk=VK.MULTIPLY),
    0x56: KeyCode(vk=VK.SUBTRACT),
    0x57: KeyCode(vk=VK.ADD),
    0x58: Key.enter,
    0x59: KeyCode(vk=VK.NUMPAD1),
    0x5A: KeyCode(vk=VK.NUMPAD2),
    0x5B: KeyCode(vk=VK.NUMPAD3),
    0x5C: KeyCode(vk=VK.NUMPAD4),
    0x5D: KeyCode(vk=VK.NUMPAD5),
    0x5E: KeyCode(vk=VK.NUMPAD6),
    0x5F: KeyCode(vk=VK.NUMPAD7),
    0x60: KeyCode(vk=VK.NUMPAD8),
    0x61: KeyCode(vk=VK.NUMPAD9),
    0x62: KeyCode(vk=VK.NUMPAD0),
    0x63: KeyCode(vk=VK.DECIMAL),
    0x64: "\\",
}

KEYMAP_COMBO = {
    0b00000001: Key.ctrl_l,
    0b00000010: Key.shift_l,
    0b00000100: Key.alt_l,
    0b00001000: Key.cmd_l,
    0b00010000: Key.ctrl_r,
    0b00100000: Key.shift_r,
    0b01000000: Key.alt_gr,
    0b10000000: Key.cmd_r,
}

NUMPAD_TO_FUNC = {
    VK.NUMPAD1: Key.end,
    VK.NUMPAD2: Key.down,
    # VK.NUMPAD3: Key.page_down,
    VK.NUMPAD4: Key.left,
    VK.NUMPAD6: Key.right,
    VK.NUMPAD7: Key.home,
    VK.NUMPAD8: Key.up,
    # VK.NUMPAD9: Key.page_up,
    VK.NUMPAD0: Key.insert,
    VK.DECIMAL: Key.delete,
}


if __name__ == "__main__":
    main()
```
