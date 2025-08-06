n = "754 2225 4124 1005 1965 1479 3219 334 36 2022 4676 1579 166 783 3009 2304 3981 2863 104 3778 60 1984 1816 423 1444 4315 4315 1414 536 2820 4445 4619 4089 4392 2148 104 1673 2907 923 703 1732 2131 4402 279 3764 4465 2948 3772 91 1491"

n = list(map(int, n.split()))

def is_prime(number):
    for num in range(2, int(number**0.5) + 1):
        if number % num == 0:
            return False
    return number

result = [x for x in n if is_prime(int(x))]
print(result[0] * result[1])
