
target = 'FRPHEVGL'.lower()
offset = 1

for offset in range(1, 26, 1):
    print(f"try to {offset}...: ", end='')
    for s in target:
        res = (ord(s) + offset)
        if res > ord('z'):
            res -= ord('z') - ord('a') + 1
        print(chr(res), end='')
    print()


def caesar_decode(sss, offset):
    for s in sss:
        res = (ord(s) + offset)
        if res > ord('z'):
            res -= ord('z') - ord('a') + 1
        print(chr(res), end='')
    print()


caesar_decode('ComeChina', 13)