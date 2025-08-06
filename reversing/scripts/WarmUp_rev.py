class Decode_flag:
    # Original disassembled code showing the key and encrypted flag in memory
    # Key is 5 bytes long with padding (0x71, 0x12, 0xCE, 0x65, 0x0C)
    # Encrypted flag is 31 bytes long
    code_info = '''
        .rodata:0000000000002010                 public key
        .rodata:0000000000002010 ; _BYTE key[16]
        .rodata:0000000000002010 key             db 71h, 12h, 0CEh, 65h, 0Ch dup(0)
        .rodata:0000000000002020                 public encrypted_flag
        .rodata:0000000000002020 ; _BYTE encrypted_flag[31]
        .rodata:0000000000002020 encrypted_flag  db 17h, 7Eh, 0AFh, 2, 4Bh, 32h, 8Dh, 31h, 37h, 69h, 0F7h
        .rodata:000000000000202B                 db 1Dh, 1Fh, 5Ah, 0FCh, 33h, 12h, 7Ch, 0BDh, 0Fh, 3Ch
        .rodata:0000000000002035                 db 22h, 0BCh, 29h, 1Bh, 5Fh, 87h, 5Dh, 37h, 58h, 0B3h
    '''

    # Original C function that decrypts the flag
    # Uses XOR encryption with a 5-byte key
    # The key is repeated cyclically (key[i & 3])
    functions = '''
        int decrypt_flag() {
            int i; // [rsp+Ch] [rbp-4h]

            printf("Decrypted flag: ");
            for ( i = 0; i <= 30; ++i )
                putchar(encrypted_flag[i] ^ key[i & 3]);
            return putchar(10);
        }
    '''

    def main(self):
        # Encrypted flag data extracted from binary
        encrypted_flag = [
            0x17, 0x7E, 0xAF, 2, 0x4B, 0x32, 0x8D, 0x31, 0x37, 0x69, 0xF7,
            0x1D, 0x1F, 0x5A, 0xFC, 0x33, 0x12, 0x7C, 0xBD, 0x0F, 0x3C,
            0x22, 0xBC, 0x29, 0x1B, 0x5F, 0x87, 0x5D, 0x37, 0x58, 0xB3
        ]

        # Decryption key extracted from binary
        # Key is 5 bytes long with padding
        key = [0x71, 0x12, 0xCE, 0x65, 0x0C]

        # Initialize empty string to store decrypted flag
        flag = ""
        # Decrypt each byte of the flag using XOR with the key
        # The key is repeated cyclically using (x & 3)
        for x in range(len(encrypted_flag)):
            flag += ''.join(chr(encrypted_flag[x] ^ key[x & 3]))

        # Print the decrypted flag
        print(flag)

class Decode_password:
    # Original disassembled code showing the password verification function
    # The function takes a password as input and compares it with a hardcoded value
    # Uses XOR with 0x42 as the decryption key
    functions = '''
        erify_password(__int64 a1) {
            int i; // [rsp+1Ch] [rbp-34h]
            __int64 s2[2]; // [rsp+20h] [rbp-30h] BYREF
            char s1[24]; // [rsp+30h] [rbp-20h] BYREF
            unsigned __int64 v5; // [rsp+48h] [rbp-8h]

            v5 = __readfsqword('(');
            s2[0] = 0x673A257671212F28LL;
            s2[1] = 0x3131122D140D2D2DLL;
            for ( i = 0; i <= 15 && *(_BYTE *)(i + a1); ++i )
                s1[i] = *(_BYTE *)(i + a1) ^ 0x42;
            return memcmp(s1, s2, 0x10uLL) == 0;
        }
    '''
    
    def main(self):
        # Hardcoded hex values extracted from binary
        # These represent the encrypted password
        s2 = [
            "673A257671212F28",
            "3131122D140D2D2D"
        ]

        # List to store the processed hex values
        little_endian = []

        # Process each hex string
        for x in s2:
            # Process each 2-character pair in reverse order
            # This converts the big-endian hex string to little-endian
            for i in range(len(x)-1, -1, -2):
                little_endian.append(f"0x{x[i-1:i+1]}")

        # Initialize empty string for the password
        password = ""
        # Decrypt each byte by XORing with 0x42
        # This reverses the encryption done in the original function
        for x in little_endian:
            password += ''.join(chr(int(x, 16) ^ 0x42))

        # Print the decrypted password
        print(password)

if __name__ == '__main__':
    Decode_password().main()
    