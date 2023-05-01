from pwn import *
context.arch = 'amd64'

with open("mama_bear", "rb") as f:
    e = f.read()

opcodes = e[0x15A1:0x1B93]

def parse(opcodes):
    offset = 0
    code = b''
    addrs = []
    while True:
        if opcodes[offset] == ord('!'):
            break
        elif opcodes[offset] == ord('&'):
            code += e[0x516:0x516+0x47]
            offset += 1
        elif opcodes[offset] == ord('-'):
            offset += 1
            code += pack(0xA2C4FF24048A, 6*8) + p64(0xdeadbeef)
            addrs.append(f"secret[{opcodes[offset] - 0x30}]")
            offset += 1
        elif opcodes[offset] == ord('#'):
            offset += 1
            x = ror(ord('W') & 7, 8, 4*8) # ord('W')는 password 값에 따라 달라짐
            code += pack(0xa166, 2*8) + p64(0xdeadbeef) + pack(0x00C8C166 | x, 4*8) + pack(0xa366, 2*8) + p64(0xdeadbeef)
            addrs.append(f"secret[{opcodes[offset] - 0x30}]")
            addrs.append(f"secret[{opcodes[offset] - 0x30}]")
            offset += 1
        else:
            code += p8(0xa0) + p64(0xdeadbeef) + pack(0x240488CCFF48, 6*8)
            addrs.append(f"secret[{opcodes[offset] - 0x30}]")
            offset += 1

    code = disasm(code)
    code = code.replace("0xdeadbeef", '{}')
    code = code.format(*addrs)

    return code

def parse2(opcodes):
    global stack
    offset = 0
    output = ''
    while True:
        if opcodes[offset] == ord('!'):
            output += 'return\n'
            break
        elif opcodes[offset] == ord('&'):
            x, y = stack.pop(), stack.pop()
            output += f'&({x}, {y})\n'
            stack += [f'ENC({x})', f'ENC({y})']
            offset += 1
        elif opcodes[offset] == ord('-'):
            offset += 1
            output += f'secret[{opcodes[offset] - 0x30}] = {stack.pop()}\n'
            offset += 1
        elif opcodes[offset] == ord('#'):
            offset += 1
            output += f'secret[{opcodes[offset] - 0x30}:{opcodes[offset] - 0x30 + 2}] = ror(secret[{opcodes[offset] - 0x30}:{opcodes[offset] - 0x30 + 2}], pw & 7, 16)\n'
            offset += 1
        else:
            stack.append(f'secret[{opcodes[offset] - 0x30}]')
            offset += 1

    return output

stack = []
for opcode in opcodes.split(b'!')[:-1]:
    print(f"[+] {(opcode + b'!').decode()}")
    print(parse2(opcode + b'!'))

# with open('output.txt', 'w') as f:
#     for opcode in opcodes.split(b'!')[:-1]:
#         print(f"[+] {(opcode + b'!').decode()}", file=f)
#         print(parse(opcode + b'!'), file=f)
#         print(file=f)
#         print(file=f)

stack = []
for opcode in opcodes.split(b'!')[:-1]:
    print(f"[+] {(opcode + b'!').decode()}")
    print(parse2(opcode + b'!'))
