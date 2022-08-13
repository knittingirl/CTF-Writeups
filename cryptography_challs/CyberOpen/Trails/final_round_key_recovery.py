import string
import time

sbox = [1, 5, 15, 2, 14, 8, 0, 9, 10, 3, 4, 12, 13, 7, 11, 6]

sbox_rev = [6, 0, 3, 9, 10, 1, 15, 13, 5, 7, 8, 14, 11, 12, 4, 2]

pbox = [0x00, 0x04, 0x08, 0x0c, 0x01, 0x05, 0x09, 0x0d,
        0x02, 0x06, 0x0a, 0x0e, 0x03, 0x07, 0x0b, 0x0f]

def decrypt_end(x, final_key):
    x = x ^ final_key
    new_x = 0
    for j in range(3,-1,-1):
        sbox_bits = (x >> (j * 4)) % 0x10
        sbox_enc = sbox_rev[sbox_bits]
        new_x += sbox_enc * (0x10 ** j)
    return new_x
file = open('output.txt', 'r')
mappings = {}

while True:
    line = file.readline()
    if not line:
        break
    if 'Enter' in line:
        cleaned = line.split('message: ')[1].strip('\n')
        for i in range(16):
            plain = int(cleaned[i*4: i*4+4], 16)
            cipher = int(file.read(16), 2)
            mappings[plain] = cipher
test_keys = {}
 
start_time = time.time()

for i in range(0, 0xffff):
    pt1 = i
    pt2 = i ^ 0xc000
    if pt2 < pt1:
        continue
    ct1 = mappings[pt1]
    ct2 = mappings[pt2]
    pt_diff = pt1 ^ pt2
    ct_diff = ct1 ^ ct2 
    for char1 in string.printable:
        for char2 in string.printable:
            key = ord(char1) * 0x100 + ord(char2)
            partial_ct1 = decrypt_end(ct1, key)
            partial_ct2 = decrypt_end(ct2, key)
            ct_diff_decr = partial_ct1 ^ partial_ct2
                                
            if ct_diff_decr == 0xbbbb: 
                if hex(key) not in test_keys.keys():
                    test_keys[hex(key)] = 1
                else:
                    test_keys[hex(key)] += 1  
    if i % 0x20 == 0:
        print(hex(i))
        print(dict(sorted(test_keys.items(), key=lambda item: item[1])))

print(dict(sorted(test_keys.items(), key=lambda item: item[1])))

end_time = time.time()
print('The process took a total time of:', end_time - start_time)