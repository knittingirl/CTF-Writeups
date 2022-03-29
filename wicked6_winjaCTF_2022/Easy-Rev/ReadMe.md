# Easy-Rev 

The description for this challenge is as follows:

*You are given a 64 bit linux executable named easy-rev.out. Execute it on your linux systems using ./easy-rev.out. It will ask for 3 passwords. Correct passwords would lead you to the flag.*

This was the easiest challenge in the reverse engineering category, and it was worth 196 points at the end of the CTF. It should be possible to solve with only the ability to run Linux executables, and a basic understanding of how to use simple reverse engineering software like Ghidra. 

My write-up will mostly focus on static analysis in Ghidra, but there's obviously a lot of different ways that you could go about this!

## Getting the First Password with ltrace:

Typically, the first step when presented with an executable file in a challenge is to actually run said file. Here, we can see that the program asks for a password, checks it, and exits out if it is incorrect.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ ./easy-rev.out
Enter the first password => aaaaaaaaaaa
Incorrect password!! Exiting...
```
This first password is actually easy to get with some dynamic analysis. Binary files can be run with a program called ltrace, which tracks calls to C library functions and prints them to the terminal. In this case, we can see that after inputting my password, strcmp() is called on that input to compare it with the string "radare2". As a result, it seems like "radare2" is the first password that the program is looking for, and this can be confirmed quickly and easily by running the program again.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ ltrace ./easy-rev.out
printf("Enter the first password => ")                                    = 28
__isoc99_scanf(0x55c0cfd18025, 0x7ffc3aee5cd6, 0, 0Enter the first password => aaaaaaaaaaa
)                      = 1
strncmp("aaaaaaaaaaa", "radare2", 140721297185998)                        = -17
printf("Incorrect password!! Exiting...")                                 = 31
Incorrect password!! Exiting...+++ exited (status 31) +++
```
## Getting the Other Two Passwords with Ghidra

Unfortunately, the second password does not seem quite so easy to derive, so at this point, we can move on to looking at the program in Ghidra. The program was not compiled with debug symbols, so there is a little bit of extra work involved in finding the main function. Basically, a pretty reliable technique for Linux binaries is to open up the entry() function. One of the main activities should be a call to __libc_start_main(), in which the first argument is a function pointer. That function pointer should correspond to the main() function, so in this case, we now know that FUN_00101155 corresponds to main and can be relabelled as such.
```
void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 in_stack_00000000;
  undefined auStack8 [8];
  
  __libc_start_main(FUN_00101155,in_stack_00000000,&stack0x00000008,FUN_00101280,FUN_001012e0,
                    param_3,auStack8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```
Now we can actually look at the main function in full. The decompiled snippet I provide below is pretty much exactly as it appears in Ghidra by default, except the function was relabelled as main, and I manually retyped the globals in the first argument of __isoc_scanf to strings. If we decode the hex of local_la to ascii (little endian), that corresponds to the radare2 password check from earlier. Then, in the second password check, the %d format string indicates that the input required is an integer. The input is later compared to 0xf, which is 15 in decimal, so the second password should be 15. Finally, the third password seems to be very similar, except the input in that case is compared with 0x539. This corresponds with 1337 in decimal, so that should be the third and final password.
```
void main(void)

{
  int local_24;
  uint local_20;
  undefined8 local_1a;
  undefined4 local_12;
  undefined2 local_e;
  int local_c;
  
  local_12 = 0;
  local_e = 0;
  local_1a = 0x32657261646172;
  printf("Enter the first password => ");
  __isoc99_scanf("%s",&local_12);
  local_c = strncmp((char *)&local_12,(char *)&local_1a,(size_t)&local_1a);
  if (local_c == 0) {
    printf("Enter the second password => ");
    __isoc99_scanf("%d",&local_20);
    if (local_20 == 0xf) {
      printf("Enter the third password => ");
      __isoc99_scanf("%d",&local_24);
      if (local_24 == 0x539) {
        printf("flag{%s_%d_%d}",&local_12,(ulong)local_20,0x539);
      }
      else {
        printf("Incorrect password!! Exiting...");
      }
    }
    else {
      printf("Incorrect password!! Exiting...");
    }
  }
  else {
    printf("Incorrect password!! Exiting...");
  }
  return;
}

```
Here it is when we input those passwords as derived above:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ ./easy-rev.out
Enter the first password => radare2
Enter the second password => 15
Enter the third password => 1337
flag{radare_15_1337}
```
As an aside, the flag that this prints out is not quite correct for what the actual challenge input wanted. This is because that during the string comparison, local_c, or rbp-0x4, ends up getting set to 0. This actually overwrites the last byte of the radare2 string that we input as the first password, causing the flag to only be printed out with radare. The intended flag was 
```
  local_c = strncmp((char *)&local_12,(char *)&local_1a,(size_t)&local_1a);
```

Thanks for reading!
