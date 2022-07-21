# CTF-Writeups

This is where I am publishing a variety of writeups. Currently, I am primarily interested in binary exploitation, so there's a lot of that.

Since I now have quite a lot of writeups, I have decided to provide a directory of pwn writeups organized by topic/difficulty level:

## Absolute Beginner Challenges

[Clutter Overflow:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/picoMini_21/clutter_overflow) Stack-based buffer overflow into another stack variable.

[Stackoverflow:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/Imaginary_CTF/stackoverflow) Another buffer overflow into another stack variable.

[Bofit:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/DawgCTF_21/Bofit) ret2win with a little reverse engineering.

## Shellcode

[Two's Company:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/MetaCTF21/Two's_Compliment) Write a shellcode that only uses even bytes.

[16-bit:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/CyberOpen22/16-bit) Write a shellcode that only uses bytes 0x30-0x39 and 0x41-0x46 (i.e. base16).

## ROP

[Vader:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/space_heroes_22/vader) Static ROP exercise that teaches calling a function with arguments on x86-64.

[Rule of Two:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/space_heroes_22/Rule%20of%20Two) Writeup demonstrates ret2libc/dynamic ROP, but a more complicated static ROP approach could also be used on the challenge.

[Speedrun:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/Imaginary_CTF/speedrun) Automated ret2libc plus the concept of a ret chain.

[Controller:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/HTB_Apocalypse_2021/controller) Reverse engineer to figure out how to trigger a buffer overflow, then ret2libc.

[Little Boi:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/MetaCTF21/Little_Boi) Basic SIGROP exercise.

[Tic-Tac-Toe:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/MetaCTF21/Tic_Tac_Toe) Logic error creates a buffer overflow, then partial overwrite to bypass PIE.

[System dROP:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/HTB_Apocalypse_2021/system_dROP) Uses the return value of the main function to control the rax register and get a write syscall to use for ret2libc.

[Close the Door:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/HTB_Apocalypse_2021/close_the_door) Uses ret2csu.

## Format String

[Harvester:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/HTB_Apocalypse_2021/Harvester) Use format string to leak canary and libc address. Also ROP with a onegadget.

[Fermat Strings:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/picoMini_21/fermat_strings) Format string vulnerability to overwrite GOT entries.

[Engine Control:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/HackyHolidays_SpaceRace/engine_control) Semi-black box (source code but no binary). Uses format string to read from and write to the GOT in order to win.

## Heap

[Arachnoid Heaven](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/HTB_Uni_Quals_21/arachnoid_heaven) Fairly simple heap grooming exercise.

[Use the Force, Luke:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/space_heroes_22/Use%20the%20Force%2C%20Luke) A straightforward demonstration of the House of Force exploit.

[Unionized:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/MetaCTF21/Unionized) Uses a logic error in a mixed data-type union to get a read-write primitive for the heap, and uses this to leak/edit a function pointer from the heap.

[Robo-quest:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/HTB%20UniCTF%20Finals%202022/Robo-quest) Tcache-based. Uses a small heap overflow into the next heap chunk to overwrite chunk size metadata and get a longer heap overflow. Also allocate and free eight same-sized tcache bins to get a libc address on the heap to be leaked, and finally overwrite the free hook with a onegadget by overwriting the forward pointer on a freed tcache chunk.

## Black-Box Pwn

[Blackhole ROP:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/space_heroes_22/Blackhole%20ROP) Uses SIGROP and a format string write, with enough leaked addresses to make it fairly straightforward.

[Push:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/CyberOpen22/push) Black-box SIGROP where I also demonstrate techniques to get leaks from a binary such as locating the pops at the end of __libc_csu_init.

## Out-of-Bounds Writes

[Guessing Game:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/RaRCTF/Guessing_Game) Uses array index bug plus a binary search to leak the canary and a libc address, allowing a short ROP with a onegadget.

[String Editor 2:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/Imaginary_CTF/string_editor_2) Uses an array index bug to overwrite a GOT entry to printf's PLT address, creating a format string vulnerability that produces helpful libc leaks.

[Epic Game:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/ICHSA_CTF_21/Epic_Game) Overflows a global variable onto the GOT table.

[COP:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/ICHSA_CTF_21/COP) Uses a logic error to overflow from one static, mmapped section of memory to another to overwrite a function pointer to part-way through the win function (to avoid a check that we can't meet). Also uses a bad random seed.

## Miscellaneous

[String Editor 1:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/Imaginary_CTF/string_editor_1) Demonstrates using a free hook overwrite to call system('/bin/sh')

[Hotel Codeifornia:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/RACTF/hotel_codeifornia) Takes advantage of strcmp's termination of comparison at a null byte.

[Environment:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/HTB_Apocalypse_2021/environment) Uses arbitrary reads and writes in the binary's functionality. Most interestingly, it demonstrates using the environ variable in libc to get a stack leak based on a libc leak.

[Robot Factory:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/HTB_Uni_Quals_21/robot_factory) Uses pthread's storage of the stack_guard on the stack to bypass the canary and execute a ROPchain.

[boring-flag-runner:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/RaRCTF/boring_flag_runner) Pwning a virtual machine esolang emulator.

[Gibson:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/CyberOpen22/gibson) ROP and format string on an s390 architecture.

[TableofContents:](https://github.com/knittingirl/CTF-Writeups/tree/main/pwn_challs/romCTF21/TableofContents) Vtables exploitation in a C++ binary.
