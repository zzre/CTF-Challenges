from pwn import *
context.log_level="error"

p = process(["gdb", "plop"])

execute = lambda x: p.sendlineafter("pwndbg>", x, timeout=0.5)

def init():
    execute("starti")
    execute("code")
    execute("handle SIGSEGV nostop pass")

def recv():
    res = p.recvuntil("pwndbg>", drop=True, timeout=0.5)
    p.sendline()
    return res.decode()

def go(cnt):
    execute("x/24i $rdi")
    res = recv()
    print(f"[{cnt}] call rdi")
    print(res)
    execute("continue")

    execute("x/3i $rax")
    res = recv()
    print(f"[{cnt}] jump rax")
    print(res)

    if "rax,QWORD PTR ds:0x1337100" in res:
        raise Exception()
    else:
        execute("continue")

    return res

init()

breakpoints = [0x15b2, 0x15bf]
for bp in breakpoints:
    execute(f"b*$code+{bp}")

execute("run << a")

try:
    cnt = 1
    while True:
        go(cnt)
        cnt += 1
except:
    p.interactive()

p.close()