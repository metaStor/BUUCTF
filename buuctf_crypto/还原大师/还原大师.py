'''
我们得到了一串神秘字符串：TASC?O3RJMV?WDJKX?ZM,问号部分是未知大写字母，
为了确定这个神秘字符串，我们通过了其他途径获得了这个字串的32位MD5码。
但是我们获得它的32位MD5码也是残缺不全，E903???4DAB????08?????51?80??8A?,
请猜出神秘字符串的原本模样，并且提交这个字串的32位MD5码作为答案。
注意：得到的 flag 请包上 flag{} 提交
'''

import hashlib

src = 'TASC?O3RJMV?WDJKX?ZM'
# 依次爆破3个?处的大写字母，计算md5找出E903开头的
for i in range(26):
    src1 = src.replace('?', chr(65 + i), 1)
    for j in range(26):
        src2 = src1.replace('?', chr(65 + j), 1)
        for k in range(26):
            src3 = src2.replace('?', chr(65 + k), 1)
            hash_res = hashlib.md5(src3.encode('utf-8')).hexdigest().upper()
            if hash_res.startswith('E903'):
                print(fr'{src3}: {hash_res}')  # flag{E9032994DABAC08080091151380478A2}
