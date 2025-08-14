'''
从开头一定为 flag{ 可知：
afZ_ -> flag
a > f ==> 5
f > l ==> 6
Z > a ==> 7
_ > g ==> 8
'''
# 结论从5开始递增
offset = 5
src = 'afZ_r9VYfScOeO_UL^RWUc'

for ch in src:
    print(chr(ord(ch) + offset), end='')  # flag{Caesar_variation}
    offset += 1

