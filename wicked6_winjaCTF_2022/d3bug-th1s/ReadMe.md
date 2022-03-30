# d3bug-th1s 

The description for this challenge is as follows:

*The space station provides a nice environment for enthusiasts to discover their potential. You are given a linux executable which says "segmentation fault" on running it. Can you find out what the binary is doing and get the flag?*

This was another fairly easy reverse-engineering challenge, and it was worth 300 points during the competition. For this challenge, I will primarily demonstrate a solution focusing on dynamic analysis with GDB/GEF, but it could definitely also be solved with static analysis and Ghidra!

## Solving the Challenge:

As usual, the first step is to actually run the challenge and see what happens. Unsurprisingly based on the challenge description, some ascii art is printed to the console, and then a segmentation fault occurs.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ ./space
 /\/\/\                            /  \
| \  / |                         /      \
|  \/  |                       /          \
|  /\  |----------------------|     /\     |
| /  \ |                      |    /  \    |
|/    \|                      |   /    \   |
|\    /|                      |  | (  ) |  |
| \  / |                      |  | (  ) |  |
|  \/  |                 /\   |  |      |  |   /\
|  /\  |                /  \  |  |      |  |  /  \
| /  \ |               |----| |  |      |  | |----|
|/    \|---------------|    | | /|   .  |\ | |    |
|\    /|               |    | /  |   .  |  \ |    |
| \  / |               |    /    |   .  |    \    |
|  \/  |               |  /      |   .  |      \  |
|  /\  |---------------|/        |   .  |        \|
| /  \ |              /   CTF   |   .  |  CTF    \
|/    \|              (          |      |           )
|/\/\/\|               |    | |--|      |--| |    |
------------------------/  \-----/  \/  \-----/  \--------
                        \\//     \\//\\//     \\//
                         \/       \/  \/       \/
Segmentation fault
```
Attempts to run the program with ltrace and strace were not super helpful, so I moved on to using GDB, which I run with the GEF wrapper for improved views of information and additional features. The program was compiled using debug symbols, so I was able to break on main, run, and step through the main() function step by step.
```
Reading symbols from ./space...
(No debugging symbols found in ./space)
gef➤  b *main
Breakpoint 1 at 0x1205
gef➤  r
```
As I stepped through the program, I noted that the ascii art was printed by a banner() function that did not seem to do much else. Much more interesting was a call to getenv() with the argument "planet"
```
0x555555555231 <main+44>        call   0x5555555550a0 <getenv@plt>
   ↳  0x5555555550a0 <getenv@plt+0>   endbr64
      0x5555555550a4 <getenv@plt+4>   bnd    jmp QWORD PTR [rip+0x2efd]        # 0x555555557fa8 <getenv@got.plt>
      0x5555555550ab <getenv@plt+11>  nop    DWORD PTR [rax+rax*1+0x0]
      0x5555555550b0 <strncmp@plt+0>  endbr64
      0x5555555550b4 <strncmp@plt+4>  bnd    jmp QWORD PTR [rip+0x2ef5]        # 0x555555557fb0 <strncmp@got.plt>
      0x5555555550bb <strncmp@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
───────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
getenv@plt (
   $rdi = 0x0000555555556443 → 0x0a0074656e616c70 ("planet"?),
   $rsi = 0x0000555555556442 → 0x0074656e616c7000,
   $rdx = 0x0000000000000000
)
```
The results of the getenv function call (in x86-64, the results of a function call are stored in the rax register by default), are then loaded into a stack variable. In another spot on the stack, ascii characters seem to be being loaded into every other byte.
```
0x555555555236 <main+49>        mov    QWORD PTR [rbp-0x30], rax
   0x55555555523a <main+53>        mov    WORD PTR [rbp-0x22], 0x6d
   0x555555555240 <main+59>        mov    WORD PTR [rbp-0x20], 0x78
   0x555555555246 <main+65>        mov    WORD PTR [rbp-0x1e], 0x61
   0x55555555524c <main+71>        mov    WORD PTR [rbp-0x1c], 0x71
   0x555555555252 <main+77>        mov    WORD PTR [rbp-0x1a], 0x72
```
Then, after various calls to strcat, the word "mars" appears on the stack, and an attempt is made to call strncmp() to compare that string with what is currently showing up as a null. If we look at some of the previous lines of assembly, the value in the first argument (this is x86-64, so that's the value in the rdi register), has been set by rax, which was set by rbp-0x30, which stored the results of the getenv() call. In short, because the typical user does not have the planet environment variable, strncmp is trying to compare a null to a string, which is causing a segfault.
```
   0x00005555555552dc <+215>:   mov    rax,QWORD PTR [rbp-0x30]
   0x00005555555552e0 <+219>:   mov    edx,0x6
   0x00005555555552e5 <+224>:   mov    rsi,rcx
   0x00005555555552e8 <+227>:   mov    rdi,rax
 → 0x5555555552eb <main+230>       call   0x5555555550b0 <strncmp@plt>
   ↳  0x5555555550b0 <strncmp@plt+0>  endbr64
      0x5555555550b4 <strncmp@plt+4>  bnd    jmp QWORD PTR [rip+0x2ef5]        # 0x555555557fb0 <strncmp@got.plt>
      0x5555555550bb <strncmp@plt+11> nop    DWORD PTR [rax+rax*1+0x0]
      0x5555555550c0 <puts@plt+0>     endbr64
      0x5555555550c4 <puts@plt+4>     bnd    jmp QWORD PTR [rip+0x2eed]        # 0x555555557fb8 <puts@got.plt>
      0x5555555550cb <puts@plt+11>    nop    DWORD PTR [rax+rax*1+0x0]
───────────────────────────────────────────────────────────────────────────────────────────── arguments (guessed) ────
strncmp@plt (
   $rdi = 0x0000000000000000,
   $rsi = 0x00007fffffffe13d → 0x710061007372616d ("mars"?),
   $rdx = 0x0000000000000006,
   $rcx = 0x00007fffffffe13d → 0x710061007372616d ("mars"?)
)
```
At this point, the simplest way to get the flag is to set the planet environment variable to mars and run the program normally:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ export planet='mars'
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ ./space
 /\/\/\                            /  \
| \  / |                         /      \
|  \/  |                       /          \
|  /\  |----------------------|     /\     |
| /  \ |                      |    /  \    |
|/    \|                      |   /    \   |
|\    /|                      |  | (  ) |  |
| \  / |                      |  | (  ) |  |
|  \/  |                 /\   |  |      |  |   /\
|  /\  |                /  \  |  |      |  |  /  \
| /  \ |               |----| |  |      |  | |----|
|/    \|---------------|    | | /|   .  |\ | |    |
|\    /|               |    | /  |   .  |  \ |    |
| \  / |               |    /    |   .  |    \    |
|  \/  |               |  /      |   .  |      \  |
|  /\  |---------------|/        |   .  |        \|
| /  \ |              /   CTF   |   .  |  CTF    \
|/    \|              (          |      |           )
|/\/\/\|               |    | |--|      |--| |    |
------------------------/  \-----/  \/  \-----/  \--------
                        \\//     \\//\\//     \\//
                         \/       \/  \/       \/

flag{off_to_mars_2022}
```
Thanks for reading!
