import re
from tkinter.constants import X

data = [
    'var_28:2.b != 0x34',
    'var_38:4.b != 0x33',
    'var_28:4.b != 0x72',
    'var_48:1.b != 0x54',
    'var_38:5.b != 0x76',
    'var_48:6.b != 0x30',
    'var_28:7.b != 0x7d',
    'var_28:6.b != 0x64',
    'var_30:7.b != 0x72',
    'var_30:5.b != 0x33',
    'var_40:0.b != 0x33',
    'var_38:6.b != 0x65',
    'var_28:3.b != 0x31',
    'var_48:5.b != 0x72',
    'var_48:0.b != 0x48', 
    'var_28:0.b != 0x33',
    'var_38:2.b != 0x2e',
    'var_40:5.b != 0x34',
    'var_48:3.b != 0x7b',
    'var_40:2.b != 0x5f',
    'var_38:0.b != 0x2e',
    'var_48:4.b != 0x62',
    'var_48:7.b != 0x6b',
    'var_40:7.b != 0x74',
    'var_40:6.b != 0x72',
    'var_38:3.b != 0x6e',
    'var_30:1.b != 0x74',
    'var_38:1.b != 0x2e',
    'var_40:1.b != 0x6e',
    'var_30:6.b != 0x5f',
    'var_30:2.b != 0x30',
    'var_30:0.b != 0x5f',
    'var_40:4.b != 0x70',
    'var_38:7.b != 0x72',
    'var_30:4.b != 0x62',
    'var_28:1.b != 0x70',
    'var_48:2.b != 0x42',
    'var_30:3.b != 0x5f',
    'var_40:3.b != 0x34',
    'var_28:5.b != 0x33',
]

new_data = []

order_list = [ 48, 40, 38, 30, 28 ]

for list_order in order_list:
    for index in range(0, 8):
        for x in data:
            new_regex = re.findall(f"var_{list_order}:{str(index)}.*", x)
            if new_regex:
                print(new_regex)

new_data = [
    0x48,
    0x54,
    0x42,
    0x7b,
    0x62,
    0x72,
    0x30,
    0x6b,
    0x33,
    0x6e,
    0x5f,
    0x34,
    0x70,
    0x34,
    0x72,
    0x74,
    0x2e,
    0x2e,
    0x2e,
    0x6e,
    0x33,
    0x76,
    0x65,
    0x72,
    0x5f,
    0x74,
    0x30,
    0x5f,
    0x62,
    0x33,
    0x5f,
    0x72,
    0x33,
    0x70,
    0x34,
    0x31,
    0x72,
    0x33,
    0x64,
    0x7d,
]

flag = ""

for x in new_data: 
    flag += ''.join(chr(x))

print(flag)