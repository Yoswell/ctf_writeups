from pwn import *

def main():
    ip = '94.237.60.55'
    port = 37214
    conn = remote(ip, port)

    def xor_bytes(b1, b2):
        return bytes([a ^ b for a, b in zip(b1, b2)])

    key = b'12345678'
    user_agent_1 = b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    user_agent_2 = b'a'

    plaintext = b'Agent aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa, your clearance for Operation Blackout is: '

    conn.sendline(key)
    conn.sendline(user_agent_1)

    conn.recvuntil(b'Encrypted transmission: ')
    ciphertext = bytes.fromhex(conn.recvline().strip().decode())
    xor_operation_1 = xor_bytes(ciphertext, plaintext)
    
    conn.sendline(key)
    conn.sendline(user_agent_2)

    conn.recvuntil(b'Encrypted transmission: ')
    ciphertext2 = bytes.fromhex(conn.recvline().strip().decode())
    xor_operation_2 = xor_bytes(ciphertext2, xor_operation_1[:len(ciphertext)])

    print(xor_operation_2)

if __name__ == '__main__':
    main()