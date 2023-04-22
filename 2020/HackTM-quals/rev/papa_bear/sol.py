import re
import shlex
import string
from pwn import *
context.log_level='error'

def init():
    global tbl
    p = process(["gdb", "papa_bear"])
    execute = lambda x: p.sendlineafter("pwndbg>", x, timeout=0.5)

    execute("b*0x601737")
    for c in string.printable[:-5]:
        execute(f"r {shlex.quote(c)}")
        execute("i r cl")
        cl = int(p.recvline().split()[1], 16)
        tbl[c] = cl

def go(ipt):
    p = process(["./papa_bear", ipt], stdin=PTY)
    res = re.sub('[^MW]', '', p.recvall().decode())
    p.close()
    return res

def dfs(ipt, plen, cl):
    print(ipt)
    res = go(ipt)

    if target == res[:len(target)]:
        print("found!")
        print(ipt)
        exit()
        
    elif target.startswith(res[:plen+cl]):
        for c, cnt in tbl.items():
            dfs(ipt+c, plen+cl, cnt)

target = '''dWWW=- dWWMWWWWWMWMb dMMWWWWWWWWWb -=MMMb
dWMWP dWWWMWWWMMWMMMWWWWWMMMMMMWMMMWWWMMMb qMWb
WMWWb dMWWMMMMMMWWWWMMWWWMWWWWWWMMWWWWMWMWMMMWWWWb dMMM
qMMWMWMMMWMMWWWMWMMMMMMMMWMMMMWWWMMWWMWMWMMWWMWWWWMWWMMWMMWP
QWWWWWWWMMWWWWWWWMMWWWWMMWP QWWWMWMMMMWWWWWMMWWMWWWWWWMP
QWMWWWMMWWMWMWWWWMWWP QWWMWWMMMWMWMWWWWMMMP
QMWWMMMP QMMMMMMP'''
target = re.sub('[^MW]', '', target)

tbl = {}
init()

for c, cnt in tbl.items():
    dfs(c, 0, cnt)
