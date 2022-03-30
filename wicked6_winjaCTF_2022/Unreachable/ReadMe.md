# Unreachable 

The description of this challenge is as follows:

*"You have to go through rough patches to achieve great things."*

This challenge was categorized as binary exploitation, although it was more of a challenge in using a debugger or patching a binary. It was worth 350 points, and it was relativel straightforward to solve.

## Solving the Challenge:

If I try to actually run the challenge, I can see that it requires me to input my password as a command line parameter, and if I input an incorrect password, I get an "Incorrect password" message.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ ./unreachable.out aaaaaaaaaaaa
 ==============================================
|                    Crack Me                  |
 ==============================================
Incorrect Password
```
I can then try opening the program up in Ghidra. 
```
undefined8 main(int param_1,undefined8 *param_2)

{
  size_t sVar1;
  
  puts(
      " ==============================================\n|                    Crack Me                  |\n =============================================="
      );
  if (param_1 == 1) {
    printf("Usage %s <password>\n",*param_2);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  sVar1 = strlen((char *)param_2[1]);
  if (sVar1 != 7) {
    puts("Incorrect Password");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  sVar1 = strlen((char *)param_2[1]);
  if (sVar1 == 5) {
    giveflag();
  }
  return 0;
}
```
Interesting! So, it looks like the program is designed so that the giveflag() function cannot be hit during normal operations, since the length of the password we submit would simultaneously have to 7 characters and 5 characters long to pass both of the checks. Now, normally in a binary exploitation challenge, you would also be given a netcat connection and required to come up with an input combination that would execute the giveflag() function, pop a shell, or otherwise meet a win condition without editing anything mid-run using a debugger. However, based on the way in which this challenge is designed, I don't think that's possible; ideally, I'd like to overflow the return pointer with the address of giveflag(), but the 7 character string length check will trigger an exit, and I can't use nulls in command line arguments.

Instead, the simplest approach is to use a debugger to edit variables during program execution. You could also patch the program in Ghidra, but I think the debugger approach is simpler. In GDB/GEF, we can look at the main function in assembly to look for an appropriate break point. At main+135, we see the call to strlen like in the Ghidra decompilation, and the results (stored in rax, as is typically the case in x86-64) are then compared with 5. So, in order to win, break of main+140, edit rax to 5, and continue. This should give us the flag.
```
gef➤  disas main
Dump of assembler code for function main:
   0x0000000000001299 <+0>:     endbr64
   0x000000000000129d <+4>:     push   rbp
...
   0x0000000000001320 <+135>:   call   0x10c0 <strlen@plt>
   0x0000000000001325 <+140>:   cmp    rax,0x5
   0x0000000000001329 <+144>:   jne    0x1335 <main+156>
   0x000000000000132b <+146>:   mov    eax,0x0
   0x0000000000001330 <+151>:   call   0x11e9 <giveflag>
   0x0000000000001335 <+156>:   mov    eax,0x0
   0x000000000000133a <+161>:   leave
   0x000000000000133b <+162>:   ret
```
So, in order to win, we can use a 7-letter password to meet the first check, break on main+140, edit rax to 5, and continue. This should give us the flag.

```
gef➤  b *main+140
Breakpoint 1 at 0x1325
gef➤  r aaaaaaa
...
→ 0x555555555325 <main+140>       cmp    rax, 0x5
   0x555555555329 <main+144>       jne    0x555555555335 <main+156>
   0x55555555532b <main+146>       mov    eax, 0x0
   0x555555555330 <main+151>       call   0x5555555551e9 <giveflag>
   0x555555555335 <main+156>       mov    eax, 0x0
   0x55555555533a <main+161>       leave
───────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "unreachable.out", stopped 0x555555555325 in main (), reason: BREAKPOINT
─────────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x555555555325 → main()
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  x/gx $rax
0x7:    Cannot access memory at address 0x7
gef➤  set $rax=5
gef➤  x/gx $rax
0x5:    Cannot access memory at address 0x5
gef➤  c
Continuing.
flag{0h_s0_y0u_kN0w_P4tch1ng}[Inferior 1 (process 377) exited normally]
```
Thanks for reading!
