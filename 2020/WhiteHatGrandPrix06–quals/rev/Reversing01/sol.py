from z3 import *

with open("output.png", 'rb') as f:
    data = list(f.read())

s = Solver()
arr = [BitVec(f'x{i}', 8) for i in range(14)]

def bvCube(bv):
    return bv * bv * bv

# 1. arr[0] == 7
s.add(arr[0] == 7)

# 2. arr[13] == 12
s.add(arr[13] == 12)

# 3. arr[m] - 52 <= 9     // 1 <= m <= 6
for i in range(1, 7):
    s.add(And(0 <= arr[i] - 52, arr[i] - 52 <= 9))

# 4. arr[n] - 77 <= 9     // 7 <= n <= 11
for i in range(7, 12):
    s.add(And(0 <= arr[i] - 77, arr[i] - 77 <= 9))

# 5. arr[12] - 34 <= 9
s.add(And(0 <= arr[12] - 34, arr[12] - 34 <= 9))

# 6. int(pow(arr[1], 3.0) + pow(arr[2], 3.0) + pow(arr[3], 3.0)) == 0x62
s.add((bvCube(arr[1]) + bvCube(arr[2]) + bvCube(arr[3])) & 0xff == 0x62)

# 7. int(pow(arr[4], 3.0) + pow(arr[5], 3.0) + pow(arr[6], 3.0) + pow(arr[7], 3.0)) == 0x6B
s.add((bvCube(arr[4]) + bvCube(arr[5]) + bvCube(arr[6]) + bvCube(arr[7])) & 0xff == 0x6B)

# 8. int(pow(arr[9], 3.0) + pow(arr[10], 3.0) + pow(arr[11], 3.0) + pow(arr[12], 3.0)) == 0xBF
s.add((bvCube(arr[9]) + bvCube(arr[10]) + bvCube(arr[11]) + bvCube(arr[12])) & 0xff == 0xBF)

def SHF(arr):
    res = 0x2FD2B4
    for i in range(len(arr)):
        res = arr[i] ^ res
        res = (res * 0x66EC73) & ((1 << 64) - 1)
    return res

def getTargetHash():
    a = list(b'Flag')
    a[0] = (a[0] + 0x7D) & 0xFF
    a[1] = (a[1] - 0x7C) & 0xFF
    a[3] = (a[3] + 0x51) & 0xFF
    return int.from_bytes(bytes(a), 'little')

def getFlag(swappedData):
    for i in range(7):
        if (swappedData[0x1000*2*i] + swappedData[0x1000*(2*i+1)]) & 1 == 0:
            swappedData[0x1000*2*i:0x1000*(2*i+1)], swappedData[0x1000*(2*i+1):0x1000*(2*i+2)] = swappedData[0x1000*(2*i+1):0x1000*(2*i+2)], swappedData[0x1000*2*i:0x1000*(2*i+1)]
    
    print(f"Flag = WhiteHat{{{SHF(swappedData)}}}")

targetHash = getTargetHash()
cnt = 1

while True:
    if s.check() != sat:
        break
    if cnt % 1000 == 0:
        print(cnt)
    cnt += 1
    
    m = s.model()
    res = [int(m[i].as_long()) for i in arr]
    for i in range(14):
        data[0x1000*i + 10] = res[i]

    if SHF(data) & 0xFFFFFFFF == targetHash:
        with open('data', 'wb') as f:
            f.write(bytes(data))
        print("found!")
        getFlag(data)
        break

    s.add(And([arr[i] == res[i] for i in range(14)]) == False)