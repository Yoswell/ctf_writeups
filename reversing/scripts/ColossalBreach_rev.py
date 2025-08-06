#!/usr/bin/python3

from operator import xor

def main():
    with open('logs', 'rb') as files:
        content = files.read()
        decrypted_password = bytes(xor(0x19, char) for char in content)
        print(decrypted_password)

if __name__ == '__main__':
    main()