from ctypes import CDLL, c_char

def main():
    # Cargar la biblioteca estándar de C (libc) para usar funciones como fopen, fseek, rand, etc.
    libc = CDLL("libc.so.6")

    # Abrir el archivo en modo lectura binaria
    # - b"flag.enc": Nombre del archivo (en bytes, como lo espera C)
    # - b"rb": Modo "read binary"
    file_open = libc.fopen(b"flag.enc", b"rb")
    if not file_open:
        print("Se produjo un error al leer el archivo")
        return

    # =============================================
    # Obtener el tamaño del archivo
    # =============================================
    # Mover el puntero al final del archivo (SEEK_END = 2)
    libc.fseek(file_open, 0, 2)
    # Obtener la posición actual (que ahora es el tamaño del archivo)
    size = libc.ftell(file_open)
    # Rebobinar el puntero al inicio del archivo para leerlo desde el principio
    libc.rewind(file_open)

    # =============================================
    # Leer el contenido del archivo
    # =============================================
    # Crear un buffer del tamaño del archivo para almacenar los datos
    prt = (c_char * size)()
    # Leer el contenido del archivo en el buffer
    # - prt: Puntero al buffer
    # - 1: Tamaño de cada elemento a leer (1 byte)
    # - size: Cantidad de elementos a leer
    # - file_open: Puntero al archivo
    libc.fread(prt, 1, size, file_open)

    # Convertir el buffer de C a un objeto bytes de Python para facilitar su manejo
    file_bytes = bytes(prt)
    # Imprimir el contenido del archivo en hexadecimal (para debugging)
    print(f"Bytes encontrados del archivo: " + ''.join(f"{x:02X}" for x in file_bytes))
    print()

    # =============================================
    # Configurar el generador de números aleatorios
    # =============================================
    # Los primeros 4 bytes son la semilla (seed) para el generador
    # - 'little': Indica que está en formato little-endian
    # - signed=True: La semilla es un entero con signo
    seed = int.from_bytes(file_bytes[:4], 'little', signed=True)
    print(f"Seed: {seed}")
    # Inicializar el generador de números aleatorios con la semilla
    libc.srand(seed)

    # =============================================
    # Descifrar el contenido
    # =============================================
    # Crear un bytearray con los bytes a descifrar (excluyendo los primeros 4 bytes de la semilla)
    decrypted = bytearray(file_bytes[4:])
    for x in range(len(decrypted)):
        # Generar dos números aleatorios para las operaciones de descifrado
        rand1 = libc.rand()  # Número aleatorio para el XOR
        rand2 = libc.rand() & 7  # Número entre 0 y 7 para la rotación

        # Rotación a la derecha:
        # 1. (decrypted[x] >> rand2): Desplaza los bits 'rand2' posiciones a la derecha
        # 2. (decrypted[x] << (8 - rand2)): Desplaza los bits (8 - rand2) posiciones a la izquierda
        # 3. | (OR): Combina ambos resultados para completar la rotación
        # 4. & 0xFF: Asegura que el resultado sea un byte válido (8 bits)
        rotated = ((decrypted[x] >> rand2) | (decrypted[x] << (8 - rand2))) & 0xFF

        # Aplicar XOR con el número aleatorio y asegurar que sea un byte válido
        decrypted[x] = (rand1 ^ rotated) & 0xFF 

    # Decodificar los bytes descifrados a una cadena (usando latin-1 para evitar errores con bytes no-ASCII)
    print(decrypted.decode('latin-1'))
    
    # Cerrar el archivo
    libc.fclose(file_open)
        
if __name__ == '__main__':
    main()