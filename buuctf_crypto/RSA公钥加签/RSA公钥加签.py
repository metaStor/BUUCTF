import rsa
import gmpy2

# openssl rsa -pubin -text -modulus -in warmup -in pub.key
'''
Public-Key: (256 bit)
Modulus:
    00:c0:33:2c:5c:64:ae:47:18:2f:6c:1c:87:6d:42:
    33:69:10:54:5a:58:f7:ee:fe:fc:0b:ca:af:5a:f3:
    41:cc:dd
Exponent: 65537 (0x10001)
Modulus=C0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD
writing RSA key
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAMAzLFxkrkcYL2wch21CM2kQVFpY9+7+
/AvKr1rzQczdAgMBAAE=
-----END PUBLIC KEY-----
'''
e = 65537
# 分解因数: http://factordb.com/
# n = int("C0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD", 16)
n = 86934482296048119190666062003494800588905656017203025617216654058378322103517  # C0332C5C64AE47182F6C1C876D42336910545A58F7EEFEFC0BCAAF5AF341CCDD ==> 十进制
p = 285960468890451637935629440372639283459
q = 304008741604601924494328155975272418463
phi = (p - 1) * (q - 1)
d = gmpy2.invert(e, phi)
d = int(d)
# print(d)

key = rsa.PrivateKey(n, e, d, p, q)
with open(r'./flag.enc', 'rb') as fp:
    f = fp.read()
    print(rsa.decrypt(f, key))
