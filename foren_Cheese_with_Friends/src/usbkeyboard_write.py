import string
import random
import os
import dpkt

def main():
    writer = USBpcapWriter("write.pcap", KEYMAP_INTL)
    with open('write_chall.txt') as typed_file:
        typed_content = iter(typed_file.read())
        
    for typed_char in typed_content:
        # {CTRL_L+SHIFT|a+b}
        if typed_char == "{":
            typed_char += next(typed_content)
            while typed_char[-1] != "}":
                typed_char += next(typed_content)

            double_combo = typed_char[1:-1].split("|")
            while len(double_combo) < 2:
                double_combo.append("")
            assert len(double_combo) == 2
            typed_combo = double_combo[0].split("+")
            typed_chars = double_combo[1].split("+")

            for char in typed_combo:
                if char:
                    writer.press_key(char)
            for char in typed_chars:
                if char:
                    writer.press_key(char)
                    writer.release_key(char)
            random.shuffle(typed_combo)
            for char in typed_combo:
                if char:
                    writer.release_key(char)

        elif typed_char in KEYMAP_INTL_SHIFT:
            key_order = [random.choice(("SHIFT_L", "SHIFT_R")), KEYMAP_INTL_SHIFT[typed_char]]
            for key in key_order:
                writer.press_key(key)
            random.shuffle(key_order)
            for key in key_order:
                writer.release_key(key)
            
        else:
            writer.press_key(typed_char)
            writer.release_key(typed_char)

    assert not any(writer.hid_data)

class USBpcapWriter:
    USB_SNAPLEN = 65535
    USB_LINKTYPE = dpkt.pcap.DLT_USBPCAP
    LEN_HID_DATA = 8
    NORMAL_KEYS_INDEX = 2

    def __init__(self, path, keymap) -> None:
        # if os.path.exists(path):
        #     raise FileExistsError(f"The file {path} already exists")
        
        self.keymap = keymap
        self.pcap = dpkt.pcap.Writer(open(path, 'wb'), self.USB_SNAPLEN, self.USB_LINKTYPE)
        self.hid_data = bytearray(b"\0" * self.LEN_HID_DATA)

        self.pcap.writepkt(USBPacket(
            pseudoheader_length=28,
            irp_id=0,
            urb_function=0xb,
            irp_information=0,
            endpoint=0x80,
            urb_transfer_type=2,
            packet_data_length=8,
            data=b"\x00\x80\x06\x00\x01\x00\x00\x12\x00"
        ), 0)
        self.pcap.writepkt(USBPacket(
            pseudoheader_length=28,
            irp_id=0,
            urb_function=8,
            irp_information=1,
            endpoint=0x80,
            urb_transfer_type=2,
            packet_data_length=18,
            data=b"\x03\x12\x01\x00\x02\x00\x00\x00\x08\xca\x04}\x00\x07\x01\x01\x02\x00\x01"
        ), 0)
        self.pcap.writepkt(USBPacket(
            pseudoheader_length=28,
            irp_id=0,
            urb_function=0xb,
            irp_information=0,
            endpoint=0x80,
            urb_transfer_type=2,
            packet_data_length=8,
            data=b"\x00\x80\x06\x00\x02\x00\x00;\x00"
        ), 0)
        self.pcap.writepkt(USBPacket(
            pseudoheader_length=28,
            irp_id=0,
            urb_function=8,
            irp_information=1,
            endpoint=0x80,
            urb_transfer_type=2,
            packet_data_length=59,
            data=b"\x03\t\x02;\x00\x02\x01\x00\xa02\t\x04\x00\x00\x01\x03\x01\x01\x00\t!\x11\x01\x00\x01\"A\x00\x07\x05\x81\x03\x08\x00\n\t\x04\x01\x00\x01\x03\x00\x00\x00\t!\x11\x01\x00\x01\"4\x00\x07\x05\x82\x03\x03\x00\n"
        ), 0)
        self.pcap.writepkt(USBPacket(
            pseudoheader_length=28,
            irp_id=0,
            urb_function=0,
            irp_information=0,
            endpoint=0,
            urb_transfer_type=2,
            packet_data_length=8,
            data=b"\x00\x00\t\x01\x00\x00\x00\x00\x00"
        ), 0)
        self.pcap.writepkt(USBPacket(
            pseudoheader_length=28,
            irp_id=0,
            urb_function=0,
            irp_information=1,
            endpoint=0x00,
            urb_transfer_type=2,
            packet_data_length=0,
            data=b"\x03"
        ), 0)

        self.timestamp = 5.0

    def press_key(self, key_str: str):
        if key_str in KEYMAP_COMBO:
            key_val = KEYMAP_COMBO[key_str]
            assert not(key_val & self.hid_data[0])

            self.hid_data[0] += key_val

        elif key_str in self.keymap:
            key_val = self.keymap[key_str]
            assert key_val not in self.hid_data[2:]

            index = 2
            while self.hid_data[index] != 0:
                index += 1

            self.hid_data[index] = key_val

        else:
            raise AssertionError(f"Key {key_str} not valid")

        self.write_usb_packet()

    def release_key(self, key_str: str):
        if key_str in KEYMAP_COMBO:
            key_val = KEYMAP_COMBO[key_str]
            assert key_val & self.hid_data[0]

            self.hid_data[0] -= key_val

        elif key_str in self.keymap:
            key_val = self.keymap[key_str]
            assert key_val in self.hid_data[2:]

            index = 2
            while self.hid_data[index] != key_val:
                index += 1

            self.hid_data[index:] = self.hid_data[index+1:] + b"\0"

        else:
            raise AssertionError(f"Key {key_str} not valid")

        self.write_usb_packet()

    def write_usb_packet(self):
        assert len(self.hid_data) == self.LEN_HID_DATA
        
        packet_in = USBPacket(irp_information=1, packet_data_length=self.LEN_HID_DATA, data=self.hid_data)
        self.timestamp += random.random()
        self.pcap.writepkt(packet_in, self.timestamp)

        packet_out = USBPacket(irp_information=0, packet_data_length=0)
        self.timestamp += random.random() / 10000
        self.pcap.writepkt(packet_out, self.timestamp)
    
class USBPacket(dpkt.Packet):
    __byte_order__ = "<"
    __hdr__ = (
        ("pseudoheader_length", "H", 27),
        ("irp_id", "Q", 0xffffac85f5e62330),    # Customizable
        ("irp_usbd_status", "I", 0),
        ("urb_function", "H", 9),
        ("irp_information", "B", 0),
        ("urb_bus_id", "H", 2),                 # Customizable
        ("device_address", "H", 2),             # Customizable
        ("endpoint", "B", 0x81),
        ("urb_transfer_type", "B", 1),
        ("packet_data_length", "I", 0),
    )

KEYMAP_INTL_SHIFT = {
    **{u: l for u, l in zip(string.ascii_uppercase, string.ascii_lowercase)},
    "~": "`",
    "!": "1",
    "@": "2",
    "#": "3",
    "$": "4",
    "%": "5",
    "^": "6",
    "&": "7",
    "*": "8",
    "(": "9",
    ")": "0",
    "_": "-",
    "+": "=",
    ":": ";",
    "\"": "\'",
    "|": "\\",
    "<": ",",
    ">": ".",
    "?": "/",    
}

KEYMAP_INTL = {
    "a": 0x04,
    "b": 0x05,
    "c": 0x06,
    "d": 0x07,
    "e": 0x08,
    "f": 0x09,
    "g": 0x0A,
    "h": 0x0B,
    "i": 0x0C,
    "j": 0x0D,
    "k": 0x0E,
    "l": 0x0F,
    "m": 0x10,
    "n": 0x11,
    "o": 0x12,
    "p": 0x13,
    "q": 0x14,
    "r": 0x15,
    "s": 0x16,
    "t": 0x17,
    "u": 0x18,
    "v": 0x19,
    "w": 0x1A,
    "x": 0x1B,
    "y": 0x1C,
    "z": 0x1D,
    "1": 0x1E,
    "2": 0x1F,
    "3": 0x20,
    "4": 0x21,
    "5": 0x22,
    "6": 0x23,
    "7": 0x24,
    "8": 0x25,
    "9": 0x26,
    "0": 0x27,
    "ENTER": 0x28,
    "\n": 0x28,
    "ESC": 0x29,
    "BACKSPACE": 0x2A,
    "TAB": 0x2B,
    " ": 0x2C,
    "-": 0x2D,
    "=": 0x2E,
    "[": 0x2F,
    "]": 0x30,
    "\\": 0x31,
    "#": 0x32,
    ";": 0x33,
    "\'": 0x34,
    "`": 0x35,
    ",": 0x36,
    ".": 0x37,
    "/": 0x38,
    "CAPS_LOCK": 0x39,
    "F1": 0x3A,
    "F2": 0x3B,
    "F3": 0x3C,
    "F4": 0x3D,
    "F5": 0x3E,
    "F6": 0x3F,
    "F7": 0x40,
    "F8": 0x41,
    "F9": 0x42,
    "F10": 0x43,
    "F11": 0x44,
    "F12": 0x45,
    # "PRINT": 0x46,
    # "SCROLL_LOCK": 0x47,
    # "PAUSE": 0x48,
    "INS": 0x49,
    "HOME": 0x4A,
    # "PAGE_UP": 0x4B,
    "DEL": 0x4C,
    "END": 0x4D,
    # "PAGE_DOWN": 0x4E,
    "RIGHT": 0x4F,
    "LEFT": 0x50,
    "DOWN": 0x51,
    "UP": 0x52,
    "NUM_LOCK": 0x53,
    "PAD_DIV": 0x54,
    "PAD_MUL": 0x55,
    "PAD_SUB": 0x56,
    "PAD_ADD": 0x57,
    "PAD_ENTER": 0x58,
    "PAD_1": 0x59,
    "PAD_2": 0x5A,
    "PAD_3": 0x5B,
    "PAD_4": 0x5C,
    "PAD_5": 0x5D,
    "PAD_6": 0x5E,
    "PAD_7": 0x5F,
    "PAD_8": 0x60,
    "PAD_9": 0x61,
    "PAD_0": 0x62,
    "PAD_.": 0x63,
}

KEYMAP_COMBO = {
    "CTRL_L": 0x01,
    "SHIFT_L": 0x02,
    "ALT": 0x04,
    "META_L": 0x08,
    "CTRL_R": 0x10,
    "SHIFT_R": 0x20,
    "ALT_GR": 0x40,
    "META_R": 0x80,
}

if __name__ == "__main__":
    main()
