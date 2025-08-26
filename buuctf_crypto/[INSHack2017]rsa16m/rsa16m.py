import gmpy2
from Crypto.Util.number import long_to_bytes

# n，c很大，相对而e很小
with open(r'./rsa_16m', 'r') as fp:
    # n = int(fp.readline().strip("\n").split("=")[1], 16)
    fp.readline()
    c = fp.readline()[4:]
    c = int(c, 16)
    print(c)
e = 0x10001

# d 的值很小，可能只有几
# d 压根没用到，d = 1，直接对c开e次方即可
m = gmpy2.iroot(c, e)[0]
print(long_to_bytes(m))
