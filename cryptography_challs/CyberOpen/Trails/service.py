#!/usr/bin/env python3

sbox = [1, 5, 15, 2, 14, 8, 0, 9, 10, 3, 4, 12, 13, 7, 11, 6]

pbox = [0x00, 0x04, 0x08, 0x0c, 0x01, 0x05, 0x09, 0x0d,
        0x02, 0x06, 0x0a, 0x0e, 0x03, 0x07, 0x0b, 0x0f]

flag = ['################',
        '################',
        '################',
        '################',
        '################'] #READACTED

xor = lambda a, b : ''.join([str(int(a[i]) ^ int(b[i])) for i in range(len(a))])

def binary(hex):
    return bin(int(hex, 16))[2:].zfill(len(hex) * 4)

def blocks(s):
    return [s[i:i+16].ljust(16, '0') for i in range(0, len(s), 16)]

def encrypt(x):
    for i in range(4):
        x = xor(x, flag[i])
        x = ''.join([bin(sbox[int(x[i:i+4], 2)])[2:].zfill(4) for i in range(0, len(x), 4)])
        if i == 3:
            x = xor(x, flag[i + 1])
        else:
            x = ''.join([x[i] for i in pbox])
    return x


try:
    m = binary(input("Enter message: "))
    print(''.join([encrypt(block) for block in blocks(m)]))
except:
    print('Invalid Input. Enter message in hex.')
