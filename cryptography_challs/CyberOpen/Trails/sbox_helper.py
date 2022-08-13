sbox = [1, 5, 15, 2, 14, 8, 0, 9, 10, 3, 4, 12, 13, 7, 11, 6]

diffs = []
for i in range(16):
    for j in range(16):
        if i != j:
            plain_diff = i ^ j
            enciphered_diff = sbox[i] ^ sbox[j]
            diffs.append(str(plain_diff) + ' => ' + str(enciphered_diff))

diffs_dict = {}

for item in diffs:
    if item not in diffs_dict.keys():
        diffs_dict[item]=1
    else:
        diffs_dict[item] += 1

print(dict(sorted(diffs_dict.items(), key=lambda item: item[1])))