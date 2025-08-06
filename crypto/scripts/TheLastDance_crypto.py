#The chacha20 common used a XOR operation

def main():
    with open("out.txt", "r") as file:
        data = file.read()

        message = data.split('\n')[1]
        flag = data.split('\n')[2]
        
        b = bytes.fromhex(message)
        c = bytes.fromhex(flag)

        combined = bytes(x ^ y for x, y in zip(b, c))

        known_message = (
            b"Our counter agencies have intercepted your messages and a lot "
            b"of your agent's identities have been exposed. In a matter of "
            b"days all of them will be captured"
        )

        flag = bytes(x ^ y for x, y in zip(known_message, combined))

        print(flag.decode())

if __name__ == "__main__":
    main()