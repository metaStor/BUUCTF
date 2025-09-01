import gmpy2
from Crypto.Util.number import *
from sympy import *
'''
from secret import flag

p = getPrime(25)
e = # Hidden
q = getPrime(25)
n = p * q
m = bytes_to_long(flag.strip(b"npuctf{").strip(b"}"))

c = pow(m, e, n)
print(c)
print(pow(2, e, n))
print(pow(4, e, n))
print(pow(8, e, n))

169169912654178
128509160179202
518818742414340
358553002064450
'''

c = 169169912654178
c_2 = 128509160179202
c_4 = 518818742414340
c_8 = 358553002064450

'''
已知三个方程组:
c_2 = 2^e mod n
c_4 = 4^e mod n = 2^(2*e) mod n = (2^e)^2 mod n = c_2^2 mod n ==> c_2^2 = k1*n + c_4
c_8 = 8^e mod n = 2^(3*e) mod n = (2^e)^3 mod n = c_2^3 mod n = (c_2^2 * c_2) mod n = c_4 * c_2 mod n ===> c_8 = k2*n + c_2*c_4 
联立两式，可求得n：
c_2^2 - c_4 = k1*n
c_8 - c_2*c_4 = k2*n
即 gcd(c_2^2 - c_4, c_8 - c_2*c_4) = n
'''
nn = gmpy2.gcd(pow(c_2, 2) - c_4, c_8 - c_2*c_4)
print(nn)
# yafu 分解n
p = 18195301
q = 28977097
n = p * q
# 已知m,c,p,q,求e，离散对数问题
# 求解 g^x = a mod n ==> discrete_log(n, a, g)
e = discrete_log(n, c_2, 2)
print(e)
d = gmpy2.invert(e, (p - 1) * (q - 1))
m = gmpy2.powmod(c, d, n)
print(long_to_bytes(m))
