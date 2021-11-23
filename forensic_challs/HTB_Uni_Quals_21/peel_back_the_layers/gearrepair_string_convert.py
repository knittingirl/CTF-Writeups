flag_list = []
flag_list.append(0x33725f317b425448)
flag_list.append(0x6b316c5f796c6c34)
flag_list.append(0x706d343374735f33)
flag_list.append(0x306230725f6b6e75)
flag_list.append(0xd0a7d2121217374)

flag = b''
for item in flag_list:
	flag += (item).to_bytes(8, byteorder='little')
print(flag)

