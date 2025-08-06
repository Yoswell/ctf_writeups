import json
from Crypto.Util.number import long_to_bytes
from pwn import *
from sympy.ntheory.modular import crt
from sympy.simplify.simplify import nthroot

class Connection():
    def __init__(self, ip, port):
        self.ip = ip
        self.port = port

    def hastad_broadcast_attack(self):
        conn = remote(self.ip, self.port)

        msg = []
        num = []

        for _ in range(10):
            conn.sendline(b'Y')
            response = conn.recvline()
            json_decode = json.loads(response[74:])

            time_capsule = json_decode['time_capsule']
            pubkey = json_decode['pubkey'][0]

            m = int(time_capsule, 16)
            n = int(pubkey, 16)

            msg.append(m)
            num.append(n)

        m = crt(num, msg, check=True)
        flag = nthroot(m[0], 5)

        print(long_to_bytes(flag))

        conn.close()

if __name__ == "__main__":
    Connection('83.136.255.39', '59892').hastad_broadcast_attack()
