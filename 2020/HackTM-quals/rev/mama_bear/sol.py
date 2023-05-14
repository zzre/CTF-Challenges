from z3 import *
from queue import deque

with open("mama_bear", "rb") as f:
    e = f.read()

opcodes = e[0x15A1:0x1B93]

def tokenizer(opcodes: str):
    res = []
    opcodes = deque(opcodes)
    while opcodes:
        opcode = opcodes.popleft()
        if opcode == '!':
            res.append(opcode)
        elif opcode == '&':
            res.append(opcode)
        elif opcode == '-':
            opcode += opcodes.popleft()
            res.append(opcode)
        elif opcode == '#':
            opcode += opcodes.popleft()
            res.append(opcode)
        else:
            res.append(opcode)
    
    return res

def go(opcode, pw):
    global stack
    for op in opcode:
        if op == '!':
            return
        
        elif op.startswith('-'):
            secret[ord(op[1]) - 0x30] = stack.pop()
        
        elif op.startswith('#'):
            idx = ord(op[1]) - 0x30
            
            val = Concat(secret[idx+1], secret[idx])
            val = RotateRight(val, 7)
            
            secret[idx] = Extract(7, 0, val)
            secret[idx+1] = Extract(15, 8, val)

        elif op.startswith('&'):
            res = [stack.pop(), stack.pop()]
            for i in range(8):
                idx = (res[0] & 1) + (res[1] & 1)*2
                tmp = Extract(7, 0, LShR(arr[pw], ZeroExt(3*8, 8*idx))) & 3
                res[1] = RotateLeft((res[1] & 0xfe) | LShR(tmp, 1), 1)
                res[0] = RotateLeft((res[0] & 0xfe) | (tmp & 1), 1)
            stack += [res[1], res[0]]
        
        else:
            stack.append(secret[ord(op[0]) - 0x30])

    return

ops = []
for opcode in opcodes.split(b'!')[1:-1]:
    ops.append(tokenizer((opcode + b'!').decode()))

s = Solver()

password = [BitVec('p%d' % i, 8) for i in range(8)]
secret = [BitVec('s%d' % i, 8) for i in range(32)]
orig_secret = [c for c in secret]
arr = Array('box', BitVecSort(8), BitVecSort(4*8))

s.add(password[0] == ord('X'))
s.add(password[7] == ord('W'))

for c in password:
    s.add(And(0x20 <= c,c <= 0x7f))

for c in orig_secret:
    s.add(And(0x20 <= c,c <= 0x7f))

stack = []
for i in range(8):
    go(ops[i], password[i])

target = bytes.fromhex("8ba409960881fbab676e7e4a47447770b365d57c186169286b2f064d0b434bf6")

for i in range(len(target)):
    s.add(secret[i] == target[i])

s.add(orig_secret[0] == ord('H'))
s.add(orig_secret[1] == ord('a'))
s.add(orig_secret[2] == ord('c'))
s.add(orig_secret[3] == ord('k'))

s.check()

m = s.model()
print(''.join([chr(m[x].as_long()) for x in orig_secret]))
