output = ''

def sub_40035C(bit):
    if bit:
        return sub_400346
    else:
        return sub_4003CD

def sub_4003CD(bit):
    global output
    output += '0'
    if bit:
        return sub_400370
    else:
        return sub_4003E1

def sub_400346(bit):
    global output
    output += '1'
    if bit:
        return sub_400457
    else:
        return sub_4003F3

def sub_400370(bit):
    global output
    output += '0'
    if bit:
        return sub_4003F3
    else:
        return sub_40037E

def sub_4003E1(bit):
    if bit:
        return sub_40037E
    else:
        return sub_400461

def sub_4003F3(bit):
    global output
    output += '1'
    if bit:
        return sub_4003A3
    else:
        return sub_40037E

def sub_400394(bit):
    if bit:
        return sub_4003A3
    else:
        return sub_400478

def sub_4003A3(bit):
    global output
    output += '0'
    if bit:
        return sub_4003B3
    else:
        return sub_40035C

def sub_40037E(bit):
    if bit:
        return sub_400394
    else:
        return sub_400478

def sub_4003B3(bit):
    global output
    output += '0'
    if bit:
        return sub_4003C7
    else:
        return sub_40035C

def sub_4003C7(bit):
    global output
    output += '1'
    if bit:
        return sub_40035C
    else:
        return sub_40011B

def sub_40011B(bit):
    if bit:
        return sub_40035C        
    else:
        return sub_400461

def sub_400461(bit):
    global output
    output += '0'
    if bit:
        return sub_400478
    else:
        return sub_400442

def sub_400478(bit):
    global output
    output += '1'
    if bit:
        return sub_4003B3
    else:
        return sub_400442

def sub_400442(bit):
    if bit:
        return sub_4003B3
    else:
        return sub_4003C7

def sub_400457(bit):
    if bit:
        return sub_4003A3
    else:
        return sub_40037E

def hash(ipt):
    global output
    output = ''
    func = sub_40035C
    ipt = int.from_bytes(ipt, 'little')
    i = 0
    while len(output) < 0x2e:
        func = func((ipt >> i) & 1)
        i += 1

    return output


ipt = b'asdfasdf\n'
print(hash(ipt))