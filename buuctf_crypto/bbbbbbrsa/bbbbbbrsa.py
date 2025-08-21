import base64

import gmpy2
from base64 import b64encode as b32encode
from base64 import b64decode
from Crypto.Util.number import *


p = 177077389675257695042507998165006460849
n = 37421829509887796274897162249367329400988647145613325367337968063341372726061
c = '==gMzYDNzIjMxUTNyIzNzIjMyYTM4MDM0gTMwEjNzgTM2UTN4cjNwIjN2QzM5ADMwIDNyMTO4UzM2cTM5kDN2MTOyUTO5YDM0czM3MjM'

'''
# 由encode.py可知：
1、密文c，是base64加密后并翻转的
2、e值的范围为: (50000,70000)
'''

c = int(b64decode(c[::-1]))

q = n // p
phi = (p - 1) * (q - 1)
for e in range(50000,70000):
    if gmpy2.gcd(e, phi) == 1:
        d = gmpy2.invert(e, phi)
        m = gmpy2.powmod(c, d, n)
        res = str(long_to_bytes(m))
        if '{' in res and '}' in res and 'flag' in res:
            print(res)

