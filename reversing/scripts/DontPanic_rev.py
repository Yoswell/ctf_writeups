in_order_list = {
    'h076f93abc7994a2b' : 'h',
    'h08f069e45c38c91b' : 'p',
    'h1e50475f0ef4e3b2' : 't',
    'h1ef6bfd22dfb1eaa' : '{',
    'h28c42c5fb55e3f9f' : '_',
    'h2ed86dfdd0fc9ca5' : 'c',
    'h32497efb348ffe3c' : 'H',
    'h3dae80a6281f81f5' : 'o',
    'h40d00bd196c3c783' : '0',
    'h4aee5a63c69b281c' : 'r',
    'h4b68f43d986eff7c' : '_',
    'h4e1d94269d5dab9f' : 'n',
    'h5935cc8a67508b36' : '1',
    'h70ddab66eb3eaf7e' : '4',
    'h784eba9476a4f0f4' : 'B',
    'h827ece763c8c7e2e' : 'T',
    'ha0a2d91800448694' : 'e',
    'hc26775751c1be756' : '{',
    'hc599f6727ca8db95' : 'd',
    'hd3a717188d9c9564' : '3',
    'he29dc24b9b003076' : '}',
}

ordered_list = [
    'h32497efb348ffe3c',
    'h827ece763c8c7e2e',
    'h784eba9476a4f0f4',
    'hc26775751c1be756',
    'hc599f6727ca8db95',
    'h40d00bd196c3c783',
    'h4e1d94269d5dab9f',
    'h1e50475f0ef4e3b2',
    'h28c42c5fb55e3f9f',
    'h08f069e45c38c91b',
    'h70ddab66eb3eaf7e',
    'h4e1d94269d5dab9f',
    'h5935cc8a67508b36',
    'h2ed86dfdd0fc9ca5',
    'h28c42c5fb55e3f9f',
    'h2ed86dfdd0fc9ca5',
    'h70ddab66eb3eaf7e',
    'h1e50475f0ef4e3b2',
    'h2ed86dfdd0fc9ca5',
    'h076f93abc7994a2b',
    'h28c42c5fb55e3f9f',
    'h1e50475f0ef4e3b2',
    'h076f93abc7994a2b',
    'ha0a2d91800448694',
    'h28c42c5fb55e3f9f',
    'hd3a717188d9c9564',
    'h4aee5a63c69b281c',
    'h4aee5a63c69b281c',
    'h3dae80a6281f81f5',
    'h4aee5a63c69b281c',
    'he29dc24b9b003076',
]

decode_flag = ''
for x in ordered_list:
    if x in in_order_list:
        decode_flag += ''.join(in_order_list[x])

print(decode_flag)