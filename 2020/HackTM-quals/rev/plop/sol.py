from z3 import *
from pwn import *
from Crypto.Util.number import long_to_bytes

s = Solver()

ans = [BitVec(f'ans{i}', 8*8) for i in range(8)]

for i in range(8):
    for j in range(8):
        c = Extract((j+1)*8 - 1, j*8, ans[i])
        s.add(And(0x20 <= c, c < 0x7f))

# flag format
s.add(Extract(7, 0, ans[0]) == ord('H'))
s.add(Extract(15, 8, ans[0]) == ord('a'))
s.add(Extract(23, 16, ans[0]) == ord('c'))
s.add(Extract(31, 24, ans[0]) == ord('k'))
s.add(Extract(39, 32, ans[0]) == ord('T'))
s.add(Extract(47, 40, ans[0]) == ord('M'))
s.add(Extract(55, 48, ans[0]) == ord('{'))

# round 1
tmp = RotateLeft(ans[0], 0xe) ^ 0xdc3126bd558bb7a5

# round 2
# s.add(tmp == 0)
s.add(ans[1] == RotateRight(tmp ^ 0x76085304e4b4ccd5, 0x28))

# round 3
s.add(RotateLeft(ans[2], 0x3e) ^ 0x1cb8213f560270a0 == tmp)

# round 4
s.add(RotateLeft(ans[3], 2) ^ 0x4ef5a9b4344c0672 == tmp)

# round 5
s.add(ans[4] == RotateRight(tmp ^ 0xe28a714820758df7, 0x2d))

# round 6
s.add(RotateLeft(ans[5], 0x27) ^ 0xa0d78b57bae31402 == tmp)

# round 7
s.add(RotateRight(ans[6] ^ rol(0x4474f2ed7223940, 0x35, 64), 0x35) == tmp)

# round 8
s.add(ans[7] == RotateRight(tmp ^ 0xb18ceeb56b236b4b, 0x19))

while True:
    if s.check() != sat:
        break

    m = s.model()
    res = [int(m[i].as_long()) for i in ans]

    print(''.join(map(lambda x: x.to_bytes(8, 'little').decode(), res)))
    check = And([ans[i] == res[i] for i in range(8)])
    s.add(check == False)