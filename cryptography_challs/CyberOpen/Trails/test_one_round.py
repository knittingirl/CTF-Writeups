sbox = [1, 5, 15, 2, 14, 8, 0, 9, 10, 3, 4, 12, 13, 7, 11, 6]

sbox_rev = [6, 0, 3, 9, 10, 1, 15, 13, 5, 7, 8, 14, 11, 12, 4, 2]

pbox = [0x00, 0x04, 0x08, 0x0c, 0x01, 0x05, 0x09, 0x0d,
        0x02, 0x06, 0x0a, 0x0e, 0x03, 0x07, 0x0b, 0x0f]
        
flag = [0xc320, 0x4323, 0x3234, 0x4240, 0x5780]

def encrypt_custom(x):
    for i in range(0,2):

        x = x ^ flag[i]

        new_x = 0
        for j in range(3,-1,-1):
            sbox_bits = (x >> (j * 4)) % 0x10
            sbox_enc = sbox[sbox_bits]
            new_x += sbox_enc * (0x10 ** j)

        if i == 1:
            new_x = new_x ^ flag[i+1]

        else:
            new_x = int(''.join([format(new_x, '016b')[i] for i in pbox]), 2)

        x = new_x
    return new_x

def decrypt_end(x, final_key):
    x = x ^ final_key
    new_x = 0
    for j in range(3,-1,-1):
        sbox_bits = (x >> (j * 4)) % 0x10
        sbox_enc = sbox_rev[sbox_bits]
        new_x += sbox_enc * (0x10 ** j)
    return new_x

test_keys = {}

for i in range(0, 0xffff):
    pt1 = i
    pt2 = i ^ 0xc000
    if pt2 < pt1:
        continue
    ct1 = encrypt_custom(pt1)
    ct2 = encrypt_custom(pt2)
    pt_diff = pt1 ^ pt2
    ct_diff = ct1 ^ ct2
    if (ct_diff % 0x10000) // 0x1000 != 0:
        continue
    if (ct_diff % 0x100) // 0x10 != 0:
        continue
    if (ct_diff % 0x10) // 0x1 != 0:
        continue
    
    for key1 in range(0x10):
        partial_ct1 = decrypt_end(ct1, key1 * 0x100)
        partial_ct2 = decrypt_end(ct2, key1 * 0x100)
        ct_diff1 = partial_ct1 ^ partial_ct2

        key = key1 * 0x100
            
        if ct_diff1 == 0x800: 
            if hex(key) not in test_keys.keys():
                test_keys[hex(key)] = 1
            else:
                test_keys[hex(key)] += 1 

print(dict(sorted(test_keys.items(), key=lambda item: item[1])))
