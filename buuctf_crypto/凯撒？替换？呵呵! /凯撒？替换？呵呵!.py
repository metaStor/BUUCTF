'''
从开头一定为 flag 可知：
MTHJ -> flag
'''
src = 'MTHJ{CUBCGXGUGXWREXIPOYAOEYFIGXWRXCHTKHFCOHCFDUCGTXZOHIXOEOWMEHZO}'

# 没有规律，应该不是基础的凯撒
print(ord('f') - ord('M'))
print(ord('l') - ord('T'))
print(ord('a') - ord('H'))
print(ord('g') - ord('J'))

# https://quipqiup.com/ 用 quipquip 进行词频分析
# rule: MTHJ=flag
# flag substitution cipher decryption is always easy just like a piece of cake
# flag{substitutioncipherdecryptionisalwayseasyjustlikeapieceofcake}

