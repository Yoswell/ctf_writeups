#!/usr/bin/python3

from ctypes import CDLL
import string

libc = CDLL("libc.so.6")

encode_flag = [
    608905406, 183990277, 286129175, 128959393, 1795081523,
    1322670498, 868603056, 677741240, 1127757600, 89789692,
    421093279, 1127757600, 1662292864, 1633333913, 1795081523,
    1819267000, 1127757600, 255697463, 1795081523, 1633333913,
    677741240, 89789692, 988039572, 114810857, 1322670498,
    214780621, 1473834340, 1633333913, 585743402
]

dicctionary = string.ascii_lowercase + string.ascii_uppercase + string.digits + "_" + "-" + "." + "{" + "}"

decode_flag = ''
for i in range(len(encode_flag)):
    for c in dicctionary:
        libc.srand(ord(c))
        if(libc.rand() == encode_flag[i]):
            decode_flag += ''.join(c)

print(decode_flag)