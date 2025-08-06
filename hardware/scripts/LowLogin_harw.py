import csv

def main():
    result = []

    with open('/home/parrot/HTB_machines/HTB_challenges/Hardware/hw_lowlogic/input.csv', 'r') as file:
        content = csv.reader(file)
        next(content)

        for x in content:
            a = int(x[0])
            b = int(x[1])
            c = int(x[2])
            d = int(x[3])

            and_1 = a & b
            and_2 = c & d

            or_1 = and_1 | and_2

            result.append(str(or_1))

    binarie_decode = ''.join(result)
    result = []

    for x in range(0, len(binarie_decode), 8):
        result.append(chr(int(binarie_decode[x:x+8], 2)))

    print(''.join(result))

if __name__ == '__main__':
    main()