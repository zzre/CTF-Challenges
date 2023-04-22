from pwn import *
from collections import deque
from Crypto.Util.number import long_to_bytes
output = ''

def sub_40035C(bit):
    if bit:
        return sub_400346, -1
    else:
        return sub_4003CD, -1

def sub_4003CD(bit):
    if bit:
        return sub_400370, 0
    else:
        return sub_4003E1, 0

def sub_400346(bit):
    if bit:
        return sub_400457, 1
    else:
        return sub_4003F3, 1

def sub_400370(bit):
    if bit:
        return sub_4003F3, 0
    else:
        return sub_40037E, 0

def sub_4003E1(bit):
    if bit:
        return sub_40037E, -1
    else:
        return sub_400461, -1

def sub_4003F3(bit):
    if bit:
        return sub_4003A3, 1
    else:
        return sub_40037E, 1

def sub_400394(bit):
    if bit:
        return sub_4003A3, -1
    else:
        return sub_400478, -1

def sub_4003A3(bit):
    if bit:
        return sub_4003B3, 0
    else:
        return sub_40035C, 0

def sub_40037E(bit):
    if bit:
        return sub_400394, -1
    else:
        return sub_400478, -1

def sub_4003B3(bit):
    if bit:
        return sub_4003C7, 0
    else:
        return sub_40035C, 0

def sub_4003C7(bit):
    if bit:
        return sub_40035C, 1
    else:
        return sub_40011B, 1

def sub_40011B(bit):
    if bit:
        return sub_40035C, -1     
    else:
        return sub_400461, -1

def sub_400461(bit):
    if bit:
        return sub_400478, 0
    else:
        return sub_400442, 0

def sub_400478(bit):
    if bit:
        return sub_4003B3, 1
    else:
        return sub_400442, 1

def sub_400442(bit):
    if bit:
        return sub_4003B3, -1
    else:
        return sub_4003C7, -1

def sub_400457(bit):
    if bit:
        return sub_4003A3, -1
    else:
        return sub_40037E, -1

def dfs(func, cur, idx, target):
    global found, ans
    if found or len(cur) > 0x10*8:
        return

    for i in range(2):
        dest, bit = func(i)
        if bit == -1:
            dfs(dest, str(i) + cur, idx, target)
        elif bit == target[idx]:
            if idx + 1 < len(target):
                dfs(dest, str(i) + cur, idx+1, target)
            else:
                found = True
                cur = str(i) + cur
                ans = long_to_bytes(int(cur, 2))[::-1]
                return

def unhash(target):
    target = deque([int(x) for x in target])
    dfs(sub_40035C, '', 0, target)

p = process("./original.baby_bear", stdin=PTY)
p.recvuntil("Baby bear says: ")
target = p.recvline()[:-1].decode()

ans = ''
found = False
unhash(target)

p.sendafter("What do you say?", ans)
p.interactive()