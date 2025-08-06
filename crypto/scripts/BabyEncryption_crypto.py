class Main:
    def __init__(self):
        self.encrypted_flag = '6e0a9372ec49a3f6930ed8723f9df6f6720ed8d89dc4937222ec7214d89d1e0e352ce0aa6ec82bf622227bb70e7fb7352249b7d893c493d8539dec8fb7935d490e7f9d22ec89b7a322ec8fd80e7f8921'
        self.encrypted_flag = bytes.fromhex(self.encrypted_flag)

    # Inverso multiplicativo modular => (((128 * char) - 18) % 256)
    def inverse(self, a, b):
        for num in range(1000):
            if a * num % b == 1:
                return num

    def decode(self):
        flag = []
        for char in self.encrypted_flag:
            flag.append(((char - 18) * self.inverse(123, 256)) % 256)
        
        print(bytes(flag))

if __name__ == '__main__':
    Main().decode()