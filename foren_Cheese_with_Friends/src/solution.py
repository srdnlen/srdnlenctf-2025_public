import os
from pynput.keyboard import Key, KeyCode, Controller, Listener
import pynput._util.win32_vks as VK
import time

def main():
    # Open keyboard file
    INITIAL_DELAY = 2
    KEYBOPARD_FILE = 'keyboard.txt'
    with open(KEYBOPARD_FILE, "r") as file:
        keystrokes = file.readlines()

    # Wait to position the cursor on an empty document
    time.sleep(INITIAL_DELAY)

    # Init variables
    numlock = True # Initial numlock
    keyboard = Controller()
    old_pressed_keys = set()

    # Stop button
    def on_press(key):
        if key == Key.f9:
            for key in KEYMAP_COMBO.values():
                keyboard.release(key)
            os._exit(1)
    listener = Listener(on_press=on_press)
    listener.start()

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

                # Handle numpad
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
            time.sleep(0.02)

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
    0x01: Key.ctrl_l,
    0x02: Key.shift_l,
    0x04: Key.alt_l,
    0x08: Key.cmd_l,
    0x10: Key.ctrl_r,
    0x20: Key.shift_r,
    0x40: Key.alt_gr,
    0x80: Key.cmd_r,
}

if __name__ == "__main__":
    main()
