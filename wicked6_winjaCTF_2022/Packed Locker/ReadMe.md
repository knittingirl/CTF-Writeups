# Packed Locker 

The description for this challenge is as follows:

*You are given a 64 bit linux executable with some defense mechanisms which will make reverse engineering difficult. Find the password!*

This was the hardest reverse-engineering challenge in the CTF, and worth 500 points. It was still fairly straightforward challenge, albeit one that requires knowledge about upx packing and basic reverse-engineering skills in the absence of debug symbols.

## Figuring Out UPX:

If I run the binary, I seem to have a fairly normal linux binary that asks for a password. Presumably, the play here is to figure out what that password is and enter it.
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ ./packed_locker
Enter the password
aaaaaaaaaaaaa
The password is incorrect
```
When I didn't get far with ltrace or strace, I moved on to Ghidra. However, the program didn't decompile very well:
```
void entry(long param_1,long param_2,undefined8 param_3,undefined8 param_4,undefined8 param_5,
          undefined8 param_6)

{
  undefined extraout_DL;
  undefined7 extraout_var;
  
  FUN_0044e086();
  FUN_0044de1a(CONCAT71(extraout_var,extraout_DL),param_1,extraout_DL,0,param_5,param_6,
               param_2 + param_1,CONCAT71(extraout_var,extraout_DL),param_4);
  return;
}
```
Now, the word "packed" in the challenge title was already quite suspicious, so I decided to check if the binary was packed with UPX, which is a common technique used by real malware to make reverse engineering more difficult. One of the more straightforward ways in which to check this is by using strings:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ strings -n10 packed_locker | grep UPX
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $
```
It definitely looks like UPX was used here! Unpacking a UPX packed binary is easy; you will need to install the upx program, then run:
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ upx -d packed_locker
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2018
UPX 3.95        Markus Oberhumer, Laszlo Molnar & John Reiser   Aug 26th 2018

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
    834064 <-    322080   38.62%   linux/amd64   packed_locker

Unpacked 1 file.
```
Great! We now have an unpacked binary.

## Deriving the Password:

The unpacked binary is a statically compiled, stripped binary. This means that none of the functions, including libc functions, are named, which will complicate the process of reverse engineering the program. However, it is still possible, especially since this is a fairly small, simple binary. The program does still have an entry() function, which, when comparing it with a binary with debug symbols, FUN_00401cad should be the main() function.
```
void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 in_stack_00000000;
  undefined auStack8 [8];
  
  FUN_00402190(FUN_00401cad,in_stack_00000000,&stack0x00000008,FUN_00402b60,FUN_00402bf0,param_3,
               auStack8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```
In our main function, we can see that a string is getting loaded into a stack variable, local_48. If we go ahead and decode it, we get a string of sUp3r_stRong_password123!#, which seems like it may be the password.
```
void main(void)

{
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined2 local_30;
  undefined local_2e;
  undefined8 local_28;
  undefined8 local_20;
  undefined8 local_18;
  undefined local_10;
  int local_c;
  
  local_28 = 0;
  local_20 = 0;
  local_18 = 0;
  local_10 = 0;
  local_48 = 0x74735f7233705573;
  local_40 = 0x7361705f676e6f52;
  local_38 = 0x33323164726f7773;
  local_30 = 0x2321;
  local_2e = 0;
  FUN_004178a0("Enter the password");
  FUN_00408e80(&DAT_0049e01b,&local_28);
  local_c = thunk_FUN_004010de(&local_28,&local_48);
  if (local_c == 0) {
    FUN_00408cf0("Congrats, the flag is flag{%s}",&local_28);
  }
  else {
    FUN_004178a0("The password is incorrect");
  }
  return;
}
```
When we input this as the password, we get the flag!
```
knittingirl@DESKTOP-C54EFL6:/mnt/c/Users/Owner/Desktop/CTF_Files/wicked6_22$ ./packed_locker
Enter the password
sUp3r_stRong_password123!#
Congrats, the flag is flag{sUp3r_stRong_password123!#}
```
Thanks for reading!
