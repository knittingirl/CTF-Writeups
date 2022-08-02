from pwn import *
import base64
import os 
import string

def extract_flag(test_file):

    os.system('convert ' + test_file + '.png ' + test_file + '.ppm')

    target = process(['./npiet', '-t', test_file + '.ppm'])

    target.sendline(b'a' * 100)

    raw = target.recvall(timeout = 1)
    
    reduced = raw.split(b'?')[-1]
    lines = reduced.split(b'\n')
    reduced_lines = []
    for line in lines:
        if b'add' in line or b'push' in line:
            reduced_lines.append(line)
   
    desired_pushes = []
    nums = []
    for i in range(len(reduced_lines)):
        if b'add' in reduced_lines[i]:
            push_line = reduced_lines[i-1]
            nums.append(push_line.split(b' ')[-1])
    print(nums)
    
    flag = ''

    for num in nums:
        for i in range(4, 6):
            attempt = chr(26 * i - int(num))
            if attempt in string.ascii_lowercase:
                break
        flag = attempt + flag
    print(flag)
    return flag

target = remote('pierated-art.chal.uiuc.tf', 1337)

for i in range(10):
    file1 = open('pierated.png', 'wb')
    print(target.recvuntil(b'(Base64):\n'))
    result = target.recvuntil(b'Enter').replace(b'\nEnter', b'')

    decoded = base64.b64decode(result)
    file1.write(decoded)
    file1.close()
    payload = extract_flag('pierated')

    target.sendline(payload)

target.interactive()